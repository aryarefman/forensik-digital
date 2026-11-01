"""Dynamic analysis lab: one isolated environment per sample.

    python -m apkfuse.lab init                 # once: golden AVD + mitmproxy CA
    python -m apkfuse.lab run samples/x.apk    # boot, install, analyse; Ctrl+C to stop
    python -m apkfuse.lab adb <case> shell ... # adb into a running case

Layout::

    base/sdk/            Android SDK (read-only inside the sandbox)
    base/golden/         clean emulator home: AVD with mitmproxy CA in /system
    base/mitmproxy/      mitmproxy CA
    base/adbhome/        key for the lab's private adb server (port 5038)
    cases/<sha12>/
        sample.apk       read-only copy of the sample
        static/          apkfuse mount (FUSE3, ro, noexec)
        env/             fuse-overlayfs (FUSE3): golden + upper, the emulator's $HOME
        upper/           every byte the emulator wrote: the forensic diff
        out/             flows.mitm, mitm.log, netns.pcap, logcat.txt, emulator.log

Isolation: the emulator runs under bubblewrap inside its own user, pid and
network namespace. The namespace has no route anywhere; its only exits are
unix sockets to mitmproxy on the host (TCP via -http-proxy, DNS via
mitmproxy's DNS mode). UDP other than DNS cannot leave. The guest itself is a
KVM virtual machine, so the sample never runs on the host kernel.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(PROJECT, "base")
SDK = os.path.join(BASE, "sdk")
GOLDEN = os.path.join(BASE, "golden")
MITM_CONF = os.path.join(BASE, "mitmproxy")
ADB_HOME = os.path.join(BASE, "adbhome")
CASES = os.path.join(PROJECT, "cases")
VENV_BIN = os.path.dirname(sys.executable)

AVD_NAME = "lab"
SYSTEM_IMAGE = "system-images;android-33;google_apis;x86_64"
ADB_SERVER_PORT = "5038"
EMU_PORT = 5554  # console; adbd is EMU_PORT + 1 inside the namespace
GUEST_PROXY_PORT = 8080

AVD_CONFIG = {
    "hw.ramSize": "4096",
    "disk.dataPartition.size": "6G",
    "hw.keyboard": "yes",
    "hw.gpu.enabled": "yes",
    "hw.gpu.mode": "swiftshader_indirect",
    "hw.audioInput": "no",
    "fastboot.forceColdBoot": "yes",
}


class LabError(RuntimeError):
    pass


def log(msg):
    print("[lab] %s" % msg, file=sys.stderr, flush=True)


# -- small helpers -----------------------------------------------------------

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(predicate, timeout, what, step=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(step)
    raise LabError("timed out waiting for %s" % what)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _need(*tools):
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        raise LabError("missing tools: %s" % " ".join(missing))


def adb_env():
    env = dict(os.environ)
    env["HOME"] = ADB_HOME
    env["ANDROID_ADB_SERVER_PORT"] = ADB_SERVER_PORT
    return env


def adb(serial, *args, check=True, capture=True, timeout=120):
    argv = [os.path.join(SDK, "platform-tools", "adb")]
    if serial:
        argv += ["-s", serial]
    res = subprocess.run(argv + list(args), env=adb_env(), timeout=timeout,
                         capture_output=capture, text=True)
    if check and res.returncode != 0:
        raise LabError("adb %s failed: %s" % (" ".join(args), (res.stderr or "").strip()))
    return res.stdout if capture else ""


# -- sandbox -----------------------------------------------------------------

def _bwrap_argv(env_dir, out_dir, command, display=True):
    """bubblewrap argv for the emulator (or avdmanager) over env_dir."""
    argv = [
        "bwrap",
        "--unshare-user", "--uid", str(os.getuid()), "--gid", str(os.getgid()),
        "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent",
        "--hostname", "apklab",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin",
        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
        "--ro-bind", "/etc", "/etc",
        "--ro-bind", "/sys", "/sys",
        "--proc", "/proc", "--dev", "/dev",
        "--dev-bind", "/dev/kvm", "/dev/kvm",
        "--tmpfs", "/tmp",
        "--ro-bind", SDK, "/sdk",
        "--bind", env_dir, "/env",
        "--bind", out_dir, "/out",
        "--chdir", "/env",
        "--clearenv",
        "--setenv", "PATH", "/sdk/emulator:/sdk/platform-tools:/usr/bin",
        "--setenv", "HOME", "/env",
        "--setenv", "ANDROID_HOME", "/sdk",
        "--setenv", "ANDROID_SDK_ROOT", "/sdk",
        "--setenv", "ANDROID_AVD_HOME", "/env/.android/avd",
        "--setenv", "LANG", "C.UTF-8",
    ]
    xauth = os.environ.get("XAUTHORITY")
    if display and os.environ.get("DISPLAY") and os.path.exists("/tmp/.X11-unix"):
        num = os.environ["DISPLAY"].split(":")[-1].split(".")[0]
        argv += ["--ro-bind", "/tmp/.X11-unix/X" + num, "/tmp/.X11-unix/X" + num,
                 "--setenv", "DISPLAY", ":" + num,
                 "--setenv", "QT_QPA_PLATFORM", "xcb"]
        if xauth and os.path.exists(xauth):
            argv += ["--ro-bind", xauth, "/tmp/.Xauthority",
                     "--setenv", "XAUTHORITY", "/tmp/.Xauthority"]
    return argv + ["--"] + list(command)


# Runs as (fake) root of a fresh user+net+pid namespace. lo is the only
# interface; socat turns the bridge sockets into the guest-facing ports, then
# the sandboxed command runs. When it exits, pid 1 exits and the kernel kills
# everything left in the namespace.
#
# Everything the guest sends crosses lo here (DNS to :53, TCP to the proxy
# port), so a capture on lo is the guest's full network view. The emulator's
# own -tcpdump does not see netsim (virtio-wifi) traffic.
_NS_SCRIPT = r"""
set -e
ulimit -c 0
ip link set lo up
br=$1; out=$2; shift 2
tcpdump -i lo -U -n -w "$out/netns.pcap" "not port %(adbd)d" 2>/dev/null &
[ -S "$br/dns.sock" ] && socat UDP-RECVFROM:53,bind=127.0.0.1,fork UNIX-CONNECT:"$br/dns.sock" &
[ -S "$br/proxy.sock" ] && socat TCP-LISTEN:%(proxy)d,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:"$br/proxy.sock" &
socat UNIX-LISTEN:"$br/adb.sock",fork TCP:127.0.0.1:%(adbd)d &
"$@"
""" % {"proxy": GUEST_PROXY_PORT, "adbd": EMU_PORT + 1}


def _ns_argv(bridge_dir, out_dir, inner):
    return ["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
            "--kill-child", "--mount", "--mount-proc", "--",
            "/bin/sh", "-c", _NS_SCRIPT, "lab-ns", bridge_dir, out_dir] + inner


def _emulator_cmd(headless, proxied, writable_system=True):
    cmd = ["/sdk/emulator/emulator", "-avd", AVD_NAME, "-port", str(EMU_PORT),
           "-no-snapshot", "-no-boot-anim", "-no-audio", "-no-metrics",
           "-gpu", "swiftshader_indirect"]
    if writable_system:
        cmd.append("-writable-system")
    if proxied:
        cmd += ["-http-proxy", "http://127.0.0.1:%d" % GUEST_PROXY_PORT,
                "-dns-server", "127.0.0.1"]
    if headless:
        cmd.append("-no-window")
    return cmd


class Procs:
    """Background processes torn down in reverse order of start."""

    def __init__(self):
        self.items = []

    def start(self, name, argv, logfile=None, **kw):
        out = open(logfile, "ab") if logfile else subprocess.DEVNULL
        proc = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True, **kw)
        self.items.append((name, proc, out))
        return proc

    def stop_all(self):
        for name, proc, out in reversed(self.items):
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT if name == "mitmdump" else signal.SIGTERM)
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    log("killing %s" % name)
                    proc.kill()
                    proc.wait()
            if out is not subprocess.DEVNULL:
                out.close()
        self.items = []


def _start_bridges(procs, bridge_dir, out_dir, proxied):
    """Host side of the namespace bridges. Returns the host adb port."""
    os.makedirs(bridge_dir, mode=0o700, exist_ok=True)
    for sock in ("dns.sock", "proxy.sock", "adb.sock"):
        try:
            os.unlink(os.path.join(bridge_dir, sock))
        except FileNotFoundError:
            pass
    if proxied:
        http_port, dns_port = _free_port(), _free_port()
        procs.start("mitmdump", [
            os.path.join(VENV_BIN, "mitmdump"),
            "--set", "confdir=" + MITM_CONF,
            "--set", "listen_host=127.0.0.1",
            "--mode", "regular@%d" % http_port,
            "--mode", "dns@%d" % dns_port,
            "-w", os.path.join(out_dir, "flows.mitm"),
        ], logfile=os.path.join(out_dir, "mitm.log"))
        _wait(lambda: _port_open(http_port), 30, "mitmproxy")
        procs.start("proxy-bridge", ["socat", "UNIX-LISTEN:%s/proxy.sock,fork" % bridge_dir,
                                     "TCP:127.0.0.1:%d" % http_port])
        procs.start("dns-bridge", ["socat", "UNIX-LISTEN:%s/dns.sock,fork" % bridge_dir,
                                   "UDP:127.0.0.1:%d" % dns_port])
        _wait(lambda: os.path.exists(os.path.join(bridge_dir, "dns.sock")), 10, "bridges")
    adb_port = _free_port()
    procs.start("adb-bridge", ["socat", "TCP-LISTEN:%d,bind=127.0.0.1,reuseaddr,fork" % adb_port,
                               "UNIX-CONNECT:%s/adb.sock" % bridge_dir])
    return adb_port


def _port_open(port):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _boot(procs, env_dir, out_dir, bridge_dir, adb_port, headless, proxied):
    # Locks record a pid from inside the previous pid namespace, which can be
    # reused by an unrelated process in the next one; callers guarantee that
    # nothing else is using env_dir.
    avd_dir = os.path.join(env_dir, ".android", "avd", AVD_NAME + ".avd")
    for name in os.listdir(avd_dir):
        if name.endswith(".lock"):
            os.unlink(os.path.join(avd_dir, name))
    emu = procs.start("emulator", _ns_argv(bridge_dir, out_dir, _bwrap_argv(
        env_dir, out_dir, _emulator_cmd(headless, proxied), display=not headless)),
        logfile=os.path.join(out_dir, "emulator.log"))
    serial = "127.0.0.1:%d" % adb_port

    def connected():
        if emu.poll() is not None:
            raise LabError("emulator exited (rc=%s), see %s/emulator.log" % (emu.returncode, out_dir))
        out = adb(None, "connect", serial, check=False)
        return "connected" in out and "unable" not in out and \
            "device" in adb(None, "devices", check=False).split(serial, 1)[-1].split("\n", 1)[0]

    log("booting emulator (cold boot, ~1-2 min)")
    _wait(connected, 300, "adb", step=2)
    _wait(lambda: adb(serial, "shell", "getprop", "sys.boot_completed", check=False).strip() == "1",
          300, "boot_completed", step=2)
    return emu, serial


def _adb_root(serial):
    adb(serial, "root", check=False)
    _wait(lambda: adb(None, "connect", serial, check=False) and
          adb(serial, "shell", "id", "-u", check=False).strip() == "0", 60, "adb root", step=2)


def _shutdown_guest(serial, emu):
    if emu.poll() is None:
        adb(serial, "shell", "reboot", "-p", check=False, timeout=20)
        try:
            emu.wait(60)
        except subprocess.TimeoutExpired:
            pass
    adb(None, "disconnect", serial, check=False)


def _unmount(path):
    if os.path.ismount(path):
        subprocess.run(["fusermount3", "-u", path], check=False)


# -- init --------------------------------------------------------------------

def _mitm_ca():
    """Generate the mitmproxy CA once; return (pem_path, android_name)."""
    pem = os.path.join(MITM_CONF, "mitmproxy-ca-cert.pem")
    if not os.path.exists(pem):
        os.makedirs(MITM_CONF, exist_ok=True)
        port = _free_port()
        proc = subprocess.Popen([os.path.join(VENV_BIN, "mitmdump"), "--set", "confdir=" + MITM_CONF,
                                 "--set", "listen_host=127.0.0.1", "-p", str(port)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _wait(lambda: os.path.exists(pem), 30, "mitmproxy CA")
        finally:
            proc.terminate()
            proc.wait()
    digest = subprocess.run(["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-noout",
                             "-in", pem], capture_output=True, text=True, check=True).stdout.strip()
    return pem, digest + ".0"


def cmd_init(args):
    _need("bwrap", "unshare", "socat", "openssl", "fuse-overlayfs", "fusermount3")
    if not os.path.exists(os.path.join(SDK, "emulator", "emulator")):
        raise LabError("SDK not found in %s" % SDK)
    if os.path.exists(os.path.join(GOLDEN, ".android", "avd", AVD_NAME + ".ini")) and not args.force:
        raise LabError("golden AVD already exists (use --force to rebuild it)")
    pem, ca_name = _mitm_ca()
    log("mitmproxy CA: %s -> /system/etc/security/cacerts/%s" % (pem, ca_name))

    os.makedirs(os.path.join(GOLDEN, ".android", "avd"), exist_ok=True)
    os.makedirs(os.path.join(ADB_HOME, ".android"), exist_ok=True)
    key = os.path.join(ADB_HOME, ".android", "adbkey")
    if not os.path.exists(key):
        adb(None, "keygen", key)
    # The emulator injects $HOME/.android/adbkey.pub into the guest, and its
    # bundled adb regenerates the pair if the private half is missing.
    for name in ("adbkey", "adbkey.pub"):
        shutil.copy(os.path.join(ADB_HOME, ".android", name), os.path.join(GOLDEN, ".android", name))

    out_dir = os.path.join(BASE, "init-logs")
    os.makedirs(out_dir, exist_ok=True)
    log("creating AVD")
    subprocess.run(_bwrap_argv(GOLDEN, out_dir, [
        "/sdk/cmdline-tools/latest/bin/avdmanager", "create", "avd", "--force",
        "-n", AVD_NAME, "-k", SYSTEM_IMAGE, "-d", "pixel_6"], display=False),
        input="no\n", text=True, check=True)
    config = os.path.join(GOLDEN, ".android", "avd", AVD_NAME + ".avd", "config.ini")
    with open(config) as fh:
        lines = [l for l in fh.read().splitlines() if l.split("=", 1)[0].strip() not in AVD_CONFIG]
    lines += ["%s=%s" % kv for kv in AVD_CONFIG.items()]
    with open(config, "w") as fh:
        fh.write("\n".join(lines) + "\n")

    procs = Procs()
    bridge_dir = "/run/user/%d/apkfuse/init" % os.getuid()
    try:
        adb_port = _start_bridges(procs, bridge_dir, out_dir, proxied=False)
        emu, serial = _boot(procs, GOLDEN, out_dir, bridge_dir, adb_port, args.headless, False)
        target = "/system/etc/security/cacerts/" + ca_name
        # The first remount only disables verity; it takes effect after a reboot.
        for attempt in range(2):
            _adb_root(serial)
            adb(serial, "remount", check=False)
            probe = adb(serial, "shell", "touch %s.w && rm %s.w && echo writable" % (target, target),
                        check=False)
            if "writable" in probe:
                break
            if attempt:
                raise LabError("/system stays read-only after remount")
            log("remount needs a reboot (verity off), rebooting")
            adb(serial, "reboot", check=False)
            _wait(lambda: adb(None, "connect", serial, check=False) and
                  adb(serial, "shell", "getprop", "sys.boot_completed", check=False).strip() == "1",
                  300, "reboot", step=3)
        adb(serial, "push", pem, target)
        adb(serial, "shell", "chmod", "644", target)
        for setting in (("global", "package_verifier_enable", "0"),
                        ("global", "verifier_verify_adb_installs", "0"),
                        ("system", "screen_off_timeout", "1800000")):
            adb(serial, "shell", "settings", "put", *setting)
        adb(serial, "shell", "sync")
        log("CA installed, shutting golden image down")
        _shutdown_guest(serial, emu)
    finally:
        procs.stop_all()
    log("golden image ready in %s" % GOLDEN)
    return 0


# -- run ---------------------------------------------------------------------

def cmd_run(args):
    _need("bwrap", "unshare", "socat", "fuse-overlayfs", "fusermount3")
    if not os.path.exists(os.path.join(GOLDEN, ".android", "avd", AVD_NAME + ".ini")):
        raise LabError("no golden image yet: run `python -m apkfuse.lab init` first")
    sha = _sha256(args.apk)
    case = os.path.join(CASES, sha[:12])
    dirs = {n: os.path.join(case, n) for n in ("static", "env", "upper", "work", "out")}
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    sample = os.path.join(case, "sample.apk")
    if not os.path.exists(sample):
        shutil.copyfile(args.apk, sample)
        os.chmod(sample, 0o444)
    for d in ("static", "env"):
        if os.path.ismount(dirs[d]):
            raise LabError("%s is already mounted: is this case running elsewhere?" % dirs[d])
    log("case %s (%s)" % (case, "continuing" if os.listdir(dirs["upper"]) else "new"))

    procs = Procs()
    bridge_dir = "/run/user/%d/apkfuse/%s" % (os.getuid(), sha[:12])
    meta = {"sha256": sha, "sample": os.path.basename(args.apk), "started": time.time(),
            "network": "offline" if args.offline else "mitmproxy"}
    emu = serial = None
    try:
        procs.start("apkfuse", [sys.executable, "-m", "apkfuse", sample, dirs["static"]],
                    logfile=os.path.join(dirs["out"], "apkfuse.log"), cwd=PROJECT)
        _wait(lambda: os.path.ismount(dirs["static"]), 60, "static mount")
        subprocess.run(["fuse-overlayfs", "-o", "lowerdir=%s,upperdir=%s,workdir=%s" % (
            GOLDEN, dirs["upper"], dirs["work"]), dirs["env"]], check=True)

        with open(os.path.join(dirs["static"], "manifest.facts")) as fh:
            package = json.load(fh).get("package")
        meta["package"] = package

        adb_port = _start_bridges(procs, bridge_dir, dirs["out"], proxied=not args.offline)
        emu, serial = _boot(procs, dirs["env"], dirs["out"], bridge_dir, adb_port,
                            args.headless, not args.offline)
        with open(os.path.join(case, "adb-serial"), "w") as fh:
            fh.write(serial + "\n")
        log("installing %s" % package)
        adb(serial, "install", "-r", "-g", sample, timeout=300)
        procs.start("logcat", [os.path.join(SDK, "platform-tools", "adb"), "-s", serial,
                               "logcat", "-v", "threadtime"],
                    logfile=os.path.join(dirs["out"], "logcat.txt"), env=adb_env())
        if args.launch and package:
            adb(serial, "shell", "monkey", "-p", package, "-c",
                "android.intent.category.LAUNCHER", "1", check=False)
        print("\nready: %s installed in an isolated emulator" % package)
        print("  adb      python -m apkfuse.lab adb %s shell" % sha[:12])
        print("  traffic  .venv/bin/mitmweb -r %s/flows.mitm  (after stop; live: tail -f mitm.log)"
              % dirs["out"])
        print("  output   %s" % dirs["out"])
        print("close the emulator window or press Ctrl+C to stop\n", flush=True)
        try:
            emu.wait()
        except KeyboardInterrupt:
            print(file=sys.stderr)
    finally:
        log("stopping")
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if emu is not None and serial:
            _shutdown_guest(serial, emu)
        procs.stop_all()
        _unmount(dirs["env"])
        _unmount(dirs["static"])
        meta["stopped"] = time.time()
        with open(os.path.join(dirs["out"], "runs.jsonl"), "a") as fh:
            fh.write(json.dumps(meta) + "\n")
        signal.signal(signal.SIGINT, signal.default_int_handler)
    log("done; environment kept in %s (delete the case dir to discard it)" % case)
    return 0


def cmd_adb(args):
    serial_file = os.path.join(CASES, args.case, "adb-serial")
    if not os.path.exists(serial_file):
        raise LabError("case %s has no adb serial (is it running?)" % args.case)
    with open(serial_file) as fh:
        serial = fh.read().strip()
    argv = [os.path.join(SDK, "platform-tools", "adb"), "-s", serial] + args.args
    return subprocess.run(argv, env=adb_env()).returncode


def main(argv=None):
    parser = argparse.ArgumentParser(prog="apkfuse.lab", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="build the golden AVD and mitmproxy CA")
    p.add_argument("--force", action="store_true", help="rebuild an existing golden AVD")
    p.add_argument("--headless", action="store_true", help="no emulator window")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("run", help="analyse an APK in its own environment")
    p.add_argument("apk")
    p.add_argument("--offline", action="store_true", help="no network at all (no mitmproxy)")
    p.add_argument("--headless", action="store_true", help="no emulator window")
    p.add_argument("--launch", action="store_true", help="start the app's launcher activity")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("adb", help="run adb against a running case")
    p.add_argument("case", help="case id (first 12 hex of sha256)")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_adb)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (LabError, subprocess.CalledProcessError) as exc:
        log("error: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
