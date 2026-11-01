"""Android binary XML (AXML) decoder, standard library only.

Handles the chunk types emitted by aapt/aapt2. Every read is bounds checked and
every loop is bounded by the enclosing chunk size, so a hostile manifest can at
worst raise :class:`AxmlError` -- it cannot hang or out-read its buffer.
"""

import struct

__all__ = [
    "AxmlError", "Document", "decode", "to_xml", "to_tree", "manifest_facts",
    "parse_string_pool", "mutf8_decode",
]

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F

UTF8_FLAG = 0x100
NO_INDEX = 0xFFFFFFFF

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AxmlError(ValueError):
    """Malformed or unsupported binary XML."""


def _u16(buf, off):
    if off + 2 > len(buf):
        raise AxmlError("truncated u16 at %d" % off)
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    if off + 4 > len(buf):
        raise AxmlError("truncated u32 at %d" % off)
    return struct.unpack_from("<I", buf, off)[0]


def mutf8_decode(raw):
    """Decode Java modified UTF-8 (`C0 80` NUL, surrogates as 3-byte forms)."""
    if b"\xc0\x80" in raw:
        raw = raw.replace(b"\xc0\x80", b"\x00")
    text = raw.decode("utf-8", "surrogatepass")
    if any("\ud800" <= ch <= "\udfff" for ch in text):
        try:
            text = text.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        except UnicodeError:
            pass
    return text


def _read_len8(buf, off):
    if off >= len(buf):
        raise AxmlError("truncated utf-8 string length")
    first = buf[off]
    if first & 0x80:
        return ((first & 0x7F) << 8) | buf[off + 1], off + 2
    return first, off + 1


def _read_len16(buf, off):
    first = _u16(buf, off)
    if first & 0x8000:
        return ((first & 0x7FFF) << 16) | _u16(buf, off + 2), off + 4
    return first, off + 2


def parse_string_pool(buf, start, end):
    """Parse a ResStringPool chunk into a list of ``str``."""
    header_size = _u16(buf, start + 2)
    chunk_size = _u32(buf, start + 4)
    if chunk_size < 8 or start + chunk_size > end:
        raise AxmlError("string pool chunk escapes its parent")
    if header_size < 28:
        raise AxmlError("string pool header too small")
    count = _u32(buf, start + 8)
    style_count = _u32(buf, start + 12)
    flags = _u32(buf, start + 16)
    strings_start = _u32(buf, start + 20)
    index_end = start + header_size + 4 * (count + style_count)
    if index_end > start + chunk_size:
        raise AxmlError("string pool index table overflows chunk")

    base = start + strings_start
    limit = start + chunk_size
    utf8 = bool(flags & UTF8_FLAG)
    out = []
    for i in range(count):
        off = base + _u32(buf, start + header_size + 4 * i)
        if off >= limit:
            raise AxmlError("string %d offset %d out of range" % (i, off))
        if utf8:
            # UTF-8 pools store the UTF-16 length first, then the byte length.
            _chars, pos = _read_len8(buf, off)
            nbytes, pos = _read_len8(buf, pos)
            if pos + nbytes > limit:
                raise AxmlError("string %d declares %d bytes past pool" % (i, nbytes))
            out.append(mutf8_decode(buf[pos:pos + nbytes]))
            continue
        _chars, pos = _read_len16(buf, off)
        stop = pos
        while stop + 1 < limit and (buf[stop] | buf[stop + 1]):
            stop += 2
        if stop + 1 >= limit:
            raise AxmlError("unterminated utf-16 string %d" % i)
        out.append(buf[pos:stop].decode("utf-16-le", "surrogatepass"))
    return out


def _chunks(buf):
    """Yield ``(type, start, body_start, chunk_end)`` for top level chunks."""
    off = 8  # skip the ResXMLTree header
    while off + 8 <= len(buf):
        ctype = _u16(buf, off)
        header_size = _u16(buf, off + 2)
        size = _u32(buf, off + 4)
        if size < 8 or header_size < 8 or header_size > size:
            raise AxmlError("bad chunk header at %d" % off)
        end = off + size
        if end > len(buf):
            raise AxmlError("chunk at %d runs past buffer" % off)
        yield ctype, off, off + header_size, end
        off = end


def _typed_value(data_type, data, pool):
    """Return ``(display, text)``: rendered XML value and semantic text."""
    if data_type == TYPE_STRING:
        if 0 <= data < len(pool):
            return '"%s"' % _xml_escape(pool[data]), pool[data]
        return '"<bad string %d>"' % data, ""
    # Values are quoted so the rendering is valid XML; ``text`` stays raw for
    # programmatic consumers such as manifest_facts.
    if data_type == TYPE_INT_BOOLEAN:
        text = "true" if data else "false"
        return '"%s"' % text, text
    if data_type == TYPE_INT_DEC:
        text = str(struct.unpack("<i", struct.pack("<I", data))[0])
        return '"%s"' % text, text
    if data_type == TYPE_INT_HEX:
        text = "0x%08x" % data
        return '"%s"' % text, text
    if data_type == TYPE_REFERENCE:
        return '"@0x%08x"' % data, "@0x%08x" % data
    if data_type == TYPE_ATTRIBUTE:
        return '"?0x%08x"' % data, ""
    if data_type == TYPE_FLOAT:
        text = repr(struct.unpack("<f", struct.pack("<I", data))[0])
        return '"%s"' % text, text
    if data_type in (TYPE_INT_COLOR_ARGB8, TYPE_INT_COLOR_RGB8,
                     TYPE_INT_COLOR_ARGB4, TYPE_INT_COLOR_RGB4):
        text = "#%08x" % data
        return '"%s"' % text, text
    if data_type == TYPE_NULL:
        return '""', ""
    return '"0x%08x"' % data, ""


def _xml_escape(text):
    out = []
    for ch in text:
        code = ord(ch)
        if ch == "&":
            out.append("&amp;")
        elif ch == "<":
            out.append("&lt;")
        elif ch == ">":
            out.append("&gt;")
        elif ch == '"':
            out.append("&quot;")
        elif ch in "\t\n\r" or 0x20 <= code < 0xD800 or 0xE000 <= code < 0xFFFE:
            out.append(ch)
        else:
            out.append("\\u%04x" % code)
    return "".join(out)


class Document:
    """Parsed XML: ordered events plus namespace prefix bindings."""

    def __init__(self):
        self.events = []    # ("start", node) | ("end", name) | ("text", str) | ns events
        self.prefixes = {}  # uri -> prefix

    def elements(self):
        for kind, payload in self.events:
            if kind == "start":
                yield payload

    def qname(self, ns, name):
        if not ns:
            return name
        prefix = self.prefixes.get(ns)
        if prefix is None:
            prefix = "android" if ns == ANDROID_NS else "ns0"
        return "%s:%s" % (prefix, name)


def decode(buf):
    """Parse binary XML bytes into a :class:`Document`."""
    if len(buf) < 8:
        raise AxmlError("file shorter than 8 bytes")
    if _u16(buf, 0) != RES_XML_TYPE:
        raise AxmlError("not a binary XML document (type 0x%04x)" % _u16(buf, 0))
    declared = _u32(buf, 4)
    if declared > len(buf):
        raise AxmlError("document truncated: header says %d bytes, have %d"
                        % (declared, len(buf)))
    if declared < len(buf):
        buf = buf[:declared]
    doc = Document()
    pool = []
    for ctype, start, body, end in _chunks(buf):
        if ctype == RES_STRING_POOL_TYPE:
            pool = parse_string_pool(buf, start, end)
        elif ctype == RES_XML_START_NAMESPACE_TYPE:
            prefix = _pool_str(pool, _u32(buf, body))
            uri = _pool_str(pool, _u32(buf, body + 4))
            doc.prefixes[uri] = prefix
            doc.events.append(("start_ns", (prefix, uri)))
        elif ctype == RES_XML_END_NAMESPACE_TYPE:
            doc.events.append(("end_ns", (_pool_str(pool, _u32(buf, body)),
                                          _pool_str(pool, _u32(buf, body + 4)))))
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            doc.events.append(("start", _parse_element(buf, body, end, pool)))
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            doc.events.append(("end", _pool_str(pool, _u32(buf, body + 4))))
        elif ctype == RES_XML_CDATA_TYPE:
            doc.events.append(("text", _pool_str(pool, _u32(buf, body))))
        # RES_XML_RESOURCE_MAP_TYPE and vendor chunks carry no XML content.
    return doc


def _pool_str(pool, idx):
    return pool[idx] if 0 <= idx < len(pool) else ""


def _parse_element(buf, body, end, pool):
    node = {
        "ns": _pool_str(pool, _u32(buf, body)),
        "name": _pool_str(pool, _u32(buf, body + 4)),
        "attrs": [],
    }
    attr_start = _u16(buf, body + 8)
    attr_size = _u16(buf, body + 10)
    attr_count = _u16(buf, body + 12)
    if attr_size < 20:
        raise AxmlError("attribute record smaller than 20 bytes")
    base = body + attr_start
    for i in range(attr_count):
        off = base + i * attr_size
        if off + 20 > end:
            raise AxmlError("attribute %d overflows its element" % i)
        data_type = buf[off + 15]
        data = _u32(buf, off + 16)
        display, text = _typed_value(data_type, data, pool)
        node["attrs"].append({
            "ns": _pool_str(pool, _u32(buf, off)),
            "name": _pool_str(pool, _u32(buf, off + 4)),
            "display": display,
            "text": text,
        })
    return node


def _attrs_text(doc, node):
    return " ".join(
        "%s=%s" % (doc.qname(a["ns"], a["name"]), a["display"]) for a in node["attrs"]
    )


def to_xml(doc):
    """Render the document as indented XML text."""
    out = ['<?xml version="1.0" encoding="utf-8"?>']
    stack = []
    root_emitted = False
    for kind, payload in doc.events:
        if kind == "start":
            indent = "  " * len(stack)
            attrs = _attrs_text(doc, payload)
            if not root_emitted:
                ns = " ".join(
                    'xmlns:%s="%s"' % (prefix, _xml_escape(uri))
                    for uri, prefix in doc.prefixes.items() if prefix
                )
                attrs = (ns + " " + attrs).strip()
                root_emitted = True
            name = doc.qname(payload["ns"], payload["name"])
            out.append("%s<%s%s>" % (indent, name, (" " + attrs) if attrs else ""))
            stack.append(name)
        elif kind == "text":
            text = payload.strip()
            if text:
                out.append("  " * len(stack) + _xml_escape(text))
        elif kind == "end":
            if not stack:
                continue
            out.append("%s</%s>" % ("  " * (len(stack) - 1), stack.pop()))
    return "\n".join(out) + "\n"


def to_tree(doc):
    """Render a flat, greppable view: one line per element, attributes inline."""
    lines = []
    stack = []
    for kind, payload in doc.events:
        if kind == "start":
            attrs = _attrs_text(doc, payload)
            name = doc.qname(payload["ns"], payload["name"])
            lines.append("%s%s%s" % ("  " * len(stack), name, (" " + attrs) if attrs else ""))
            stack.append(name)
        elif kind == "end" and stack:
            stack.pop()
    return "\n".join(lines) + ("\n" if lines else "")


COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def manifest_facts(doc):
    """Extract the facts a triage pass needs, including component reached-ness."""
    facts = {
        "package": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "debuggable": False,
        "allow_backup": None,
        "uses_cleartext": None,
        "permissions": [],
        "components": [],
    }
    stack = []          # element names
    component = None    # component dict currently being populated
    component_depth = None
    for kind, payload in doc.events:
        if kind == "start":
            name = payload["name"]
            attrs = {a["name"]: a["text"] for a in payload["attrs"]}
            if name == "manifest":
                facts["package"] = attrs.get("package")
                facts["version_name"] = attrs.get("versionName")
                facts["version_code"] = attrs.get("versionCode")
            elif name == "uses-sdk":
                facts["min_sdk"] = attrs.get("minSdkVersion")
                facts["target_sdk"] = attrs.get("targetSdkVersion")
            elif name == "application":
                facts["debuggable"] = attrs.get("debuggable") == "true"
                facts["allow_backup"] = attrs.get("allowBackup")
                facts["uses_cleartext"] = attrs.get("usesCleartextTraffic")
            elif name in ("uses-permission", "uses-permission-sdk-23"):
                perm = attrs.get("name")
                if perm:
                    facts["permissions"].append(perm)
            elif name in COMPONENT_TAGS:
                component = {
                    "type": name,
                    "name": attrs.get("name"),
                    "exported": attrs.get("exported"),
                    "permission": attrs.get("permission"),
                    "actions": [],
                }
                component_depth = len(stack)
                facts["components"].append(component)
            elif name == "action" and component is not None:
                action = attrs.get("name")
                if action:
                    component["actions"].append(action)
            stack.append(name)
        elif kind == "end":
            if stack:
                stack.pop()
            if component is not None and len(stack) == component_depth:
                component = None
                component_depth = None
    return facts
