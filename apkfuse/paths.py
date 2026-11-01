"""Path sanitization for hostile archive entry names.

Zip entry names are attacker controlled. This module maps them onto names that
are safe to expose through FUSE without losing the ability to tell which entry
produced which name: unsafe bytes are percent-encoded (reversible), reserved
names are escaped, overlong segments are truncated with a stable hash suffix.
"""

import hashlib
import re

__all__ = ["sanitize_component", "sanitize_path", "MAX_SEGMENT_BYTES"]

# Long enough for every real tool, short enough for NAME_MAX=255 minus escapes.
MAX_SEGMENT_BYTES = 200

_UNSAFE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_component(part):
    """Return a filesystem-safe version of one path component."""
    if part in ("", "."):
        return "%2e" if part == "." else ""
    if part == "..":
        return "%2e%2e"
    # Escape '%' first so the mapping stays injective, then control characters
    # so a name cannot forge lines in reports or logs.
    part = part.replace("%", "%25")
    part = _UNSAFE.sub(lambda m: "%%%02x" % ord(m.group()), part)
    raw = part.encode("utf-8", "surrogatepass")
    if len(raw) > MAX_SEGMENT_BYTES:
        digest = hashlib.sha256(raw).hexdigest()[:8]
        # Trim on a character boundary, not a byte boundary.
        head = raw[:MAX_SEGMENT_BYTES - 9].decode("utf-8", "ignore")
        part = "%s~%s" % (head, digest)
    return part


def sanitize_path(name):
    """Map a zip entry name to a relative, safe path.

    Returns ``(relpath, notes)`` where notes records every lossy step.
    """
    notes = []
    stripped = name.rstrip("/")
    if stripped != name:
        notes.append("trailing-slash")
    parts = stripped.split("/")
    safe = []
    for part in parts:
        if part == "":
            notes.append("empty-component")
            continue
        out = sanitize_component(part)
        if out != part:
            notes.append("escaped:%s->%s" % (part, out))
        if out:
            safe.append(out)
    if not safe:
        return None, notes + ["empty-path"]
    return "/".join(safe), notes
