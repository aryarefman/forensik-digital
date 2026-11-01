"""Build a bubblewrap command that runs an analysis tool against a mount.

The tool sees only:

    /apk     the apkfuse mount, read-only (and noexec at the FUSE layer)
    /out     the output directory, read-write
    /usr, /etc read-only, plus fresh /proc, /dev and an empty /tmp

All namespaces are unshared, so there is no network, no view of host
processes, and no access to $HOME or the project directory. This protects the
host from a parser bug in the tool being exploited by a hostile sample; the
sample itself is never executed.
"""

import os
import shutil

__all__ = ["build_argv", "SandboxError"]

APK_DIR = "/apk"
OUT_DIR = "/out"


class SandboxError(RuntimeError):
    """bubblewrap is missing or the requested layout is unusable."""


def _tiocsti_blocked():
    try:
        with open("/proc/sys/dev/tty/legacy_tiocsti") as fh:
            return fh.read().strip() == "0"
    except OSError:
        return False


def build_argv(mountpoint, outdir, command):
    """Return the argv that runs ``command`` inside the sandbox."""
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise SandboxError("bwrap not found (pacman -S bubblewrap)")
    if not command:
        raise SandboxError("no command given")
    argv = [
        bwrap,
        "--unshare-all", "--die-with-parent",
        "--hostname", "apkfuse",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/bin", "/sbin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib", "/lib64",
        "--ro-bind", "/etc", "/etc",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--ro-bind", os.path.abspath(mountpoint), APK_DIR,
        "--bind", os.path.abspath(outdir), OUT_DIR,
        "--chdir", OUT_DIR,
        "--clearenv",
        "--setenv", "PATH", "/usr/bin",
        "--setenv", "HOME", "/tmp",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "TERM", os.environ.get("TERM", "dumb"),
    ]
    # A new session stops TIOCSTI keystroke injection into the host terminal,
    # but also costs job control in an interactive shell. Kernels with
    # legacy_tiocsti=0 already block the ioctl, so only pay that cost when needed.
    if not _tiocsti_blocked():
        argv.append("--new-session")
    return argv + ["--"] + list(command)
