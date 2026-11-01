"""Read-only FUSE3 filesystem exposing an APK as a triage tree.

Layout::

    /raw/...                 verbatim zip entries, sanitized names
    /AndroidManifest.xml     decoded AXML
    /manifest.tree           flat element/attribute view (greppable)
    /manifest.facts          JSON triage summary
    /classes/<dex>.txt       class, superclass, methods, fields per dex
    /strings/<dex>.txt       string pool, one per line
    /report/integrity.txt    issues plus original name -> exposed path mapping
    /report/summary.json     machine readable summary

Everything is materialized at mount time into memory: APKs are small, and
lazy decoding inside a FUSE callback turns a malformed sample into a hang
instead of a clean error.

The mount is served through libfuse3 (pyfuse3) with ``ro,nosuid,nodev,noexec``
so nothing inside the sample can be executed straight from the mount.
"""

import errno
import hashlib
import json
import os
import signal
import stat
import struct
import time
import zipfile

import pyfuse3
import trio

from . import axml, dexindex, paths

__all__ = ["ApkFs", "build_tree", "mount", "serve", "MOUNT_OPTIONS"]

DEX_MAX = 64
# Header sizes are attacker controlled, but zipfile stops reading at
# file_size, so checking it before reading bounds memory (zip bombs).
MAX_ENTRY_BYTES = 512 << 20
MAX_TOTAL_BYTES = 2 << 30

MOUNT_OPTIONS = frozenset({
    "fsname=apkfuse", "subtype=apkfuse",
    "ro", "nosuid", "nodev", "noexec", "default_permissions",
})


class Node:
    """An in-memory file or directory."""

    __slots__ = ("children", "data", "mtime", "ino")

    def __init__(self, data=None, mtime=None):
        self.children = {} if data is None else None
        self.data = data
        self.mtime = mtime if mtime is not None else time.time()
        self.ino = None

    @property
    def is_dir(self):
        return self.children is not None


def _mkdir(root, path):
    node = root
    for part in path.split("/"):
        child = node.children.get(part)
        if child is None:
            child = node.children[part] = Node()
        elif child.data is not None:
            raise ValueError("path %s collides with a file" % path)
        node = child
    return node


def _add_file(root, path, data):
    parent, _, name = path.rpartition("/")
    where = _mkdir(root, parent) if parent else root
    where.children[name] = Node(data if isinstance(data, bytes) else data.encode("utf-8"))


def _unique(tree_dir, name, notes):
    """Reserve a name inside a directory, appending a counter on collision."""
    if name not in tree_dir.children:
        tree_dir.children[name] = Node()
        return name
    notes.append("collision:%s" % name)
    stem, _, ext = name.rpartition(".")
    if not stem:
        stem, ext = name, ""
    for i in range(2, 10000):
        candidate = "%s~%d%s" % (stem, i, ("." + ext) if ext else "")
        if candidate not in tree_dir.children:
            tree_dir.children[candidate] = Node()
            return candidate
    raise ValueError("too many name collisions for %s" % name)


def _mkdir_raw(raw, parent, notes):
    """Create ``parent`` under raw/, renaming components that are files.

    A hostile zip can hold both ``lib`` and ``lib/x.so``; the rename is
    deterministic so later entries under ``lib/`` land in the same place.
    Returns ``(node, exposed_parent)``.
    """
    node = raw
    exposed = []
    for part in parent.split("/"):
        name = part
        while name in node.children and not node.children[name].is_dir:
            name += "~dir"
        if name != part:
            notes.append("dir-collision:%s->%s" % (part, name))
        node = node.children.setdefault(name, Node())
        exposed.append(name)
    return node, "/".join(exposed)


def build_tree(apk_path):
    """Parse ``apk_path`` and return ``(root_node, report_dict)``."""
    root = Node()
    raw = _mkdir(root, "raw")
    report = {
        "apk": os.path.basename(apk_path),
        "size": os.path.getsize(apk_path),
        "sha256": None,
        "entries": 0,
        "directories": 0,
        "dex_files": [],
        "issues": [],
        "manifest": None,
    }
    digest = hashlib.sha256()
    with open(apk_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    report["sha256"] = digest.hexdigest()

    mapping = []
    total = 0
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("not a readable zip: %s" % exc)

    with zf:
        for info in zf.infolist():
            if info.is_dir():
                report["directories"] += 1
                continue
            if info.file_size > MAX_ENTRY_BYTES or total + info.file_size > MAX_TOTAL_BYTES:
                report["issues"].append("oversized entry %r (%d bytes) skipped" % (
                    info.filename, info.file_size))
                continue
            relpath, notes = paths.sanitize_path(info.filename)
            if relpath is None:
                report["issues"].append("unnamed entry %r skipped" % info.filename)
                continue
            parent, _, base = relpath.rpartition("/")
            if parent:
                target_dir, parent = _mkdir_raw(raw, parent, notes)
            else:
                target_dir = raw
            name = _unique(target_dir, base, notes)
            exposed = (parent + "/" + name) if parent else name
            if info.flag_bits & 0x1:
                # Android ignores the encryption bit; malware sets it to break
                # zip tooling. Read the entry as stored and flag it.
                info.flag_bits &= ~0x1
                notes.append("fake-encryption-flag")
                report["issues"].append("encryption flag set on %r (ignored, as Android does)"
                                        % info.filename)
            try:
                data = zf.read(info)
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError) as exc:
                report["issues"].append("unreadable %r: %s" % (info.filename, exc))
                del target_dir.children[name]
                continue
            for note in notes:
                if note.startswith("collision:"):
                    # A duplicate entry name is a classic overlay trick.
                    report["issues"].append(
                        "duplicate entry %r stored as %s" % (info.filename, exposed))
            target_dir.children[name] = Node(data, _zip_mtime(info))
            mapping.append((info.filename, exposed, info.file_size, notes))
            report["entries"] += 1
            total += len(data)

        _decode_manifest(root, zf, report)

    _index_dex(root, mapping, report)
    _write_reports(root, report, mapping)
    return root, report


def _zip_mtime(info):
    try:
        return time.mktime(info.date_time + (0, 0, -1))
    except (OverflowError, ValueError):
        return time.time()


def _decode_manifest(root, zf, report):
    try:
        raw = zf.read("AndroidManifest.xml")
    except KeyError:
        report["issues"].append("AndroidManifest.xml missing")
        return
    except (RuntimeError, zipfile.BadZipFile, KeyError, OSError) as exc:
        report["issues"].append("AndroidManifest.xml unreadable: %s" % exc)
        return
    try:
        doc = axml.decode(raw)
    except axml.AxmlError as exc:
        report["issues"].append("AndroidManifest.xml not decodable: %s" % exc)
        return
    _add_file(root, "AndroidManifest.xml", axml.to_xml(doc))
    _add_file(root, "manifest.tree", axml.to_tree(doc))
    facts = axml.manifest_facts(doc)
    facts["component_count"] = len(facts["components"])
    report["manifest"] = facts
    _add_file(root, "manifest.facts", json.dumps(facts, indent=2, sort_keys=True) + "\n")


def _index_dex(root, mapping, report):
    dex_names = sorted(
        exposed for _orig, exposed, _size, _notes in mapping
        if exposed.endswith(".dex") and exposed.count("/") <= 1
    )[:DEX_MAX]
    _mkdir(root, "classes")
    _mkdir(root, "strings")
    for exposed in dex_names:
        node = _lookup(root, "raw/" + exposed)
        if node is None or node.data is None:
            continue
        label = exposed.replace("/", "_")
        try:
            dex = dexindex.Dex(node.data)
            classes = list(dex.classes())
            strings = dex.strings
        except (dexindex.DexError, struct.error) as exc:
            report["issues"].append("%s not indexable: %s" % (exposed, exc))
            continue
        n_methods = sum(len(c["methods"]) for c in classes)
        n_fields = sum(len(c["fields"]) for c in classes)
        lines = ["# %s  classes=%d methods=%d fields=%d strings=%d" % (
            exposed, len(classes), n_methods, n_fields, len(strings))]
        for klass in classes:
            lines.append("%s extends %s%s" % (
                klass["name"], klass["super"] or "-",
                ("  # " + klass["source"]) if klass["source"] else ""))
            for name, desc in klass["methods"]:
                lines.append("  m %s%s" % (name, desc))
            for name, desc in klass["fields"]:
                lines.append("  f %s %s" % (name, desc))
        _add_file(root, "classes/" + label + ".txt", "\n".join(lines) + "\n")
        _add_file(root, "strings/" + label + ".txt", "\n".join(strings) + "\n")
        report["dex_files"].append({
            "entry": exposed,
            "classes": len(classes),
            "methods": n_methods,
            "fields": n_fields,
            "strings": len(strings),
        })
    if not report["dex_files"]:
        report["issues"].append("no indexable dex found")


def _lookup(root, relpath):
    node = root
    for part in relpath.split("/"):
        if node.children is None or part not in node.children:
            return None
        node = node.children[part]
    return node


def _write_reports(root, report, mapping):
    report_dir = _mkdir(root, "report")
    lines = ["apk: %s" % report["apk"],
             "size: %d" % report["size"],
             "sha256: %s" % report["sha256"],
             "entries: %d" % report["entries"],
             "dex-indexed: %d" % len(report["dex_files"]),
             "",
             "== issues =="]
    lines.extend(report["issues"] or ["none"])
    lines.append("")
    lines.append("== entries ==")
    for original, exposed, size, notes in mapping:
        lines.append("%s\t%d\t%s%s" % (
            exposed, size, original, ("\t" + ",".join(notes)) if notes else ""))
    _add_file(root, "report/integrity.txt", "\n".join(lines) + "\n")
    _add_file(root, "report/summary.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
    if report_dir is None:  # pragma: no cover - _mkdir always returns a node
        raise AssertionError("report directory missing")


class ApkFs(pyfuse3.Operations):
    """Read-only FUSE3 operations over a pre-built tree.

    Inodes are assigned once at construction; the tree never changes, so the
    kernel may cache entries and attributes for as long as it likes.
    """

    supports_dot_lookup = False
    CACHE_TIMEOUT = 3600

    def __init__(self, root):
        super().__init__()
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.nodes = {}     # inode -> Node
        self.listings = {}  # inode -> sorted [(name, Node)] for directories
        stack = [root]
        while stack:
            node = stack.pop()
            node.ino = pyfuse3.ROOT_INODE + len(self.nodes)
            self.nodes[node.ino] = node
            if node.is_dir:
                self.listings[node.ino] = sorted(node.children.items())
                stack.extend(node.children.values())

    def _get(self, inode):
        node = self.nodes.get(inode)
        if node is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        return node

    def _attr(self, node):
        attr = pyfuse3.EntryAttributes()
        attr.st_ino = node.ino
        attr.entry_timeout = attr.attr_timeout = self.CACHE_TIMEOUT
        if node.is_dir:
            attr.st_mode = stat.S_IFDIR | 0o555
            attr.st_nlink = 2 + sum(1 for c in node.children.values() if c.is_dir)
            attr.st_size = 0
        else:
            attr.st_mode = stat.S_IFREG | 0o444
            attr.st_nlink = 1
            attr.st_size = len(node.data)
        attr.st_uid = self.uid
        attr.st_gid = self.gid
        attr.st_blksize = 4096
        attr.st_blocks = (attr.st_size + 511) // 512
        attr.st_atime_ns = attr.st_mtime_ns = attr.st_ctime_ns = int(node.mtime * 1e9)
        return attr

    async def lookup(self, parent_inode, name, ctx=None):
        parent = self._get(parent_inode)
        if not parent.is_dir:
            raise pyfuse3.FUSEError(errno.ENOTDIR)
        child = parent.children.get(os.fsdecode(name))
        if child is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        return self._attr(child)

    async def getattr(self, inode, ctx=None):
        return self._attr(self._get(inode))

    async def opendir(self, inode, ctx):
        if not self._get(inode).is_dir:
            raise pyfuse3.FUSEError(errno.ENOTDIR)
        return inode

    async def readdir(self, fh, start_id, token):
        listing = self.listings[fh]
        for i in range(start_id, len(listing)):
            name, child = listing[i]
            if not pyfuse3.readdir_reply(token, os.fsencode(name), self._attr(child), i + 1):
                return

    async def open(self, inode, flags, ctx):
        if flags & os.O_ACCMODE != os.O_RDONLY or flags & (os.O_TRUNC | os.O_APPEND):
            raise pyfuse3.FUSEError(errno.EROFS)
        if self._get(inode).is_dir:
            raise pyfuse3.FUSEError(errno.EISDIR)
        return pyfuse3.FileInfo(fh=inode, keep_cache=True)

    async def read(self, fh, off, size):
        return self.nodes[fh].data[off:off + size]

    async def access(self, inode, mode, ctx):
        node = self._get(inode)
        if mode & os.W_OK:
            return False
        return not (mode & os.X_OK and not node.is_dir)

    async def statfs(self, ctx):
        st = pyfuse3.StatvfsData()
        st.f_bsize = st.f_frsize = 4096
        st.f_blocks = 1
        st.f_bfree = st.f_bavail = 0
        st.f_files = len(self.nodes)
        st.f_ffree = st.f_favail = 0
        st.f_namemax = 255
        return st

    # Read-only: every mutation path is explicitly refused, even if the
    # mount were ever made without "ro".
    async def _readonly(self, *args, **kwargs):
        raise pyfuse3.FUSEError(errno.EROFS)

    setattr = mknod = mkdir = unlink = rmdir = symlink = rename = link = _readonly
    create = write = setxattr = removexattr = _readonly


async def _watch_signals(scope, outcome, ignore_sigint):
    with trio.open_signal_receiver(signal.SIGINT, signal.SIGTERM, signal.SIGHUP) as signals:
        async for signum in signals:
            # With a sandboxed command in the foreground, Ctrl+C belongs to it;
            # we unmount once it exits.
            if signum == signal.SIGINT and ignore_sigint:
                continue
            outcome["rc"] = 128 + signum
            scope.cancel()
            return


async def _serve(command):
    outcome = {"rc": 0}
    async with trio.open_nursery() as nursery:
        nursery.start_soon(_watch_signals, nursery.cancel_scope, outcome, command is not None)
        if command is not None:
            async def run_command():
                proc = await trio.run_process(command, check=False, stdin=None)
                outcome["rc"] = proc.returncode
                nursery.cancel_scope.cancel()
            nursery.start_soon(run_command)
        # Returns on its own if someone runs `fusermount3 -u` on the mount.
        await pyfuse3.main()
        nursery.cancel_scope.cancel()
    return outcome["rc"]


def serve(root, mountpoint, debug=False, command=None):
    """Mount ``root`` on ``mountpoint`` and block until unmounted.

    With ``command`` (an argv list), run it while mounted and unmount when it
    exits. Returns the command's exit status, 128+signal if interrupted,
    else 0.
    """
    options = set(MOUNT_OPTIONS)
    if debug:
        options.add("debug")
    pyfuse3.init(ApkFs(root), mountpoint, options)
    try:
        return trio.run(_serve, command)
    finally:
        pyfuse3.close(unmount=True)


def mount(apk_path, mountpoint, debug=False, command=None):
    """Build the tree for ``apk_path`` and serve it. Returns ``(rc, report)``."""
    root, report = build_tree(apk_path)
    return serve(root, mountpoint, debug=debug, command=command), report
