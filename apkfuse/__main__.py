"""Command line entry point: mount an APK read-only under a directory.

    python -m apkfuse sample.apk mnt                      # mount until Ctrl+C
    python -m apkfuse sample.apk mnt -- jadx -d /out/src /apk/raw/classes.dex
                                                          # run a tool sandboxed, then unmount
"""

import argparse
import os
import sys

from . import fs, sandbox


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="apkfuse",
        description="Mount an APK read-only (FUSE3) with decoded manifest and dex indexes. "
                    "Anything after -- runs in a network-less bubblewrap sandbox that sees "
                    "the mount at /apk and --out at /out; the mount is removed when it exits.")
    parser.add_argument("apk", help="APK file to expose")
    parser.add_argument("mountpoint", help="empty directory to mount on")
    parser.add_argument("-d", "--debug", action="store_true", help="FUSE debug output to stderr")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON on mount")
    parser.add_argument("--out", help="host directory exposed as /out to the sandboxed command "
                                      "(default: out/<apk name>)")
    parser.usage = "%(prog)s [options] apk mountpoint [-- CMD [ARGS...]]"
    if argv is None:
        argv = sys.argv[1:]
    # Split by hand: argparse.REMAINDER would also swallow options like --out.
    command = []
    if "--" in argv:
        split = argv.index("--")
        argv, command = argv[:split], argv[split + 1:]
    args = parser.parse_args(argv)

    if not os.path.isfile(args.apk):
        parser.error("%s is not a file" % args.apk)
    if not os.path.isdir(args.mountpoint):
        parser.error("%s is not a directory" % args.mountpoint)
    if os.listdir(args.mountpoint):
        parser.error("%s is not empty" % args.mountpoint)

    try:
        root, report = fs.build_tree(args.apk)
    except ValueError as exc:
        print("apkfuse: %s" % exc, file=sys.stderr)
        return 1

    run = None
    if command:
        outdir = args.out or os.path.join(
            "out", os.path.splitext(os.path.basename(args.apk))[0])
        os.makedirs(outdir, exist_ok=True)
        try:
            run = sandbox.build_argv(args.mountpoint, outdir, command)
        except sandbox.SandboxError as exc:
            print("apkfuse: %s" % exc, file=sys.stderr)
            return 1

    if args.json:
        import json
        print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    print("mounting %s on %s" % (args.apk, args.mountpoint), file=sys.stderr)
    print("sha256 %s, %d entries, %d dex indexed, %d issues" % (
        report["sha256"], report["entries"], len(report["dex_files"]),
        len(report["issues"])), file=sys.stderr)
    if run:
        print("sandbox: /apk=%s (ro) /out=%s (rw), no network" % (
            args.mountpoint, outdir), file=sys.stderr)

    try:
        return fs.serve(root, args.mountpoint, debug=args.debug, command=run)
    except RuntimeError as exc:
        print("apkfuse: mount failed: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
