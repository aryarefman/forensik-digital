"""DEX string/class/method indexer, standard library only.

Only the header, the string table and the type/class/method id tables are read,
so a 100 MB multi-dex APK is indexed in milliseconds without disassembling code.
All table offsets are validated against the file length before use.
"""

import struct

__all__ = ["DexError", "Dex"]

NO_INDEX = 0xFFFFFFFF
HEADER_SIZE = 0x70
ENDIAN_CONSTANT = 0x12345678


class DexError(ValueError):
    """Malformed or unsupported DEX file."""


class Dex:
    """A parsed DEX file: strings, types, classes, methods, fields."""

    def __init__(self, buf):
        if len(buf) < HEADER_SIZE:
            raise DexError("file shorter than a DEX header")
        if buf[:4] != b"dex\n" or buf[7:8] != b"\x00":
            raise DexError("bad DEX magic")
        (endian,) = struct.unpack_from("<I", buf, 0x28)
        if endian != ENDIAN_CONSTANT:
            raise DexError("unsupported endianness 0x%08x" % endian)
        self.buf = buf
        # Offsets from the start of the file: header_size is at 0x24, and each
        # (size, offset) pair follows in 8-byte steps up to class_defs at 0x60.
        self._header = struct.unpack_from("<19I", buf, 0x24)

        self.string_ids_size, self.string_ids_off = self._table(5, 4, "string_ids")
        self.type_ids_size, self.type_ids_off = self._table(7, 4, "type_ids")
        self.proto_ids_size, self.proto_ids_off = self._table(9, 12, "proto_ids")
        self.field_ids_size, self.field_ids_off = self._table(11, 8, "field_ids")
        self.method_ids_size, self.method_ids_off = self._table(13, 8, "method_ids")
        self.class_defs_size, self.class_defs_off = self._table(15, 32, "class_defs")

        self._strings = None
        self._types = None

    def _table(self, index, entry_size, name):
        """Validate a (size, offset) header pair and return it."""
        size = self._header[index]
        off = self._header[index + 1]
        if size == 0:
            return 0, 0
        if off < HEADER_SIZE or off + size * entry_size > len(self.buf):
            raise DexError("%s table escapes file (size=%d off=0x%x)" % (name, size, off))
        return size, off

    # -- string table -----------------------------------------------------
    @property
    def strings(self):
        if self._strings is None:
            out = []
            buf = self.buf
            for i in range(self.string_ids_size):
                (data_off,) = struct.unpack_from("<I", buf, self.string_ids_off + 4 * i)
                out.append(self._read_mutf8(data_off))
            self._strings = out
        return self._strings

    def _read_mutf8(self, off):
        buf = self.buf
        if off >= len(buf):
            raise DexError("string data offset %d past EOF" % off)
        pos = off
        # Skip the ULEB128 utf16_size; the terminator bounds the actual data.
        while pos < len(buf) and buf[pos] & 0x80:
            pos += 1
        pos += 1
        end = buf.find(b"\x00", pos)
        if end < 0:
            end = len(buf)
        raw = buf[pos:end]
        if b"\xc0\x80" in raw:
            raw = raw.replace(b"\xc0\x80", b"\x00")
        return raw.decode("utf-8", "backslashreplace")

    # -- type table -------------------------------------------------------
    @property
    def types(self):
        if self._types is None:
            strings = self.strings
            out = []
            for i in range(self.type_ids_size):
                (idx,) = struct.unpack_from("<I", self.buf, self.type_ids_off + 4 * i)
                out.append(strings[idx] if idx < len(strings) else "")
            self._types = out
        return self._types

    # -- higher level views ----------------------------------------------
    def classes(self):
        """Yield one dict per class definition, with the members it declares."""
        types = self.types
        strings = self.strings
        for i in range(self.class_defs_size):
            base = self.class_defs_off + 32 * i
            class_idx, _flags, super_idx, _ifaces, source_idx, _ann, data_off = struct.unpack_from(
                "<7I", self.buf, base)
            methods, fields = self._class_data(data_off)
            yield {
                "name": _deref(types, class_idx),
                "super": _deref(types, super_idx),
                "source": _deref(strings, source_idx),
                "methods": methods,
                "fields": fields,
            }

    def _class_data(self, data_off):
        """Parse a class_data_item into ``([(name, desc)], [(name, desc)])``."""
        if not data_off:
            return [], []
        pos = data_off
        static_fields, pos = _uleb128(self.buf, pos)
        instance_fields, pos = _uleb128(self.buf, pos)
        direct_methods, pos = _uleb128(self.buf, pos)
        virtual_methods, pos = _uleb128(self.buf, pos)
        fields = []
        for _ in range(static_fields + instance_fields):
            idx_diff, pos = _uleb128(self.buf, pos)
            _flags, pos = _uleb128(self.buf, pos)
            fields.append(_field_ref(self.buf, self.field_ids_size, self.field_ids_off,
                                     self.types, self.strings, idx_diff))
        # Method index diffs restart at zero for the virtual block, so the two
        # blocks are decoded independently.
        methods = []
        for block in (direct_methods, virtual_methods):
            idx = 0
            for _ in range(block):
                idx_diff, pos = _uleb128(self.buf, pos)
                _flags, pos = _uleb128(self.buf, pos)
                _code_off, pos = _uleb128(self.buf, pos)
                idx += idx_diff
                methods.append(self._method_ref(idx))
        return methods, fields

    def _method_ref(self, method_idx):
        if method_idx >= self.method_ids_size:
            raise DexError("method index %d out of range" % method_idx)
        _class_idx, proto_idx, name_idx = struct.unpack_from(
            "<HHI", self.buf, self.method_ids_off + 8 * method_idx)
        return (_deref(self.strings, name_idx), self._proto_desc(proto_idx))

    def _proto_desc(self, proto_idx):
        if proto_idx >= self.proto_ids_size:
            raise DexError("proto index %d out of range" % proto_idx)
        (_shorty, return_idx, params_off) = struct.unpack_from(
            "<III", self.buf, self.proto_ids_off + 12 * proto_idx)
        types = self.types
        params = []
        if params_off:
            if params_off + 4 > len(self.buf):
                raise DexError("type_list offset past EOF")
            (count,) = struct.unpack_from("<I", self.buf, params_off)
            if params_off + 4 + 2 * count > len(self.buf):
                raise DexError("type_list overruns file")
            for j in range(count):
                (type_idx,) = struct.unpack_from("<H", self.buf, params_off + 4 + 2 * j)
                params.append(_deref(types, type_idx))
        return "(%s)%s" % ("".join(params), _deref(types, return_idx))

    def method_refs(self):
        """Yield ``(class, name, descriptor)`` for every method id (references)."""
        types = self.types
        strings = self.strings
        proto_by_idx = {}
        for i in range(self.method_ids_size):
            class_idx, proto_idx, name_idx = struct.unpack_from(
                "<HHI", self.buf, self.method_ids_off + 8 * i)
            proto = proto_by_idx.get(proto_idx)
            if proto is None:
                proto = proto_by_idx[proto_idx] = self._proto_desc(proto_idx)
            yield _deref(types, class_idx), _deref(strings, name_idx), proto

    def field_refs(self):
        """Yield ``(class, name, descriptor)`` for every field id (references)."""
        types = self.types
        strings = self.strings
        for i in range(self.field_ids_size):
            class_idx, type_idx, name_idx = struct.unpack_from(
                "<HHI", self.buf, self.field_ids_off + 8 * i)
            yield _deref(types, class_idx), _deref(strings, name_idx), _deref(types, type_idx)


def _uleb128(buf, pos):
    """Decode an unsigned LEB128 value, returning ``(value, next_pos)``."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise DexError("truncated uleb128")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 35:
            raise DexError("uleb128 longer than 5 bytes")


def _field_ref(buf, field_count, field_off, types, strings, idx):
    if idx >= field_count:
        raise DexError("field index %d out of range" % idx)
    _class_idx, type_idx, name_idx = struct.unpack_from("<HHI", buf, field_off + 8 * idx)
    return (_deref(strings, name_idx), _deref(types, type_idx))


def _deref(table, idx):
    if idx == NO_INDEX or idx >= len(table):
        return ""
    return table[idx]
