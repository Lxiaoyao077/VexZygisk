#!/usr/bin/env python3
"""Fails when a built binary grows past its size budget.

libzygisk.so statically links five engines (csoloader, PLTI, Dobby, LSPlt
and the LZMA decoder), so a careless dependency can balloon it unnoticed.
The limits sit roughly 15% above the sizes measured when the budget was
introduced; raise them deliberately when a feature genuinely needs the
space, and re-measure both flavours when the loader's dependency set
changes.

Usage: ci_size_budget.py [root ...]

With no arguments every entry is checked; with arguments only the entries
below one of the given build-tree roots (e.g. build, build-apatch).
"""

import os
import sys

BUDGET_KIB = {
    "build/obj/release/loader/arm64-v8a/stripped/libzygisk.so": 430,
    "build/obj/release/loader/armeabi-v7a/stripped/libzygisk.so": 330,
    "build/obj/release/loader/arm64-v8a/stripped/libzygisk_ptrace.so": 100,
    "build/obj/release/loader/armeabi-v7a/stripped/libzygisk_ptrace.so": 100,
    "build/obj/release/zygiskd/arm64-v8a/zygiskd": 56,
    "build/obj/release/zygiskd/armeabi-v7a/zygiskd": 52,
    "build-apatch/obj/release/loader/arm64-v8a/stripped/libzygisk.so": 430,
    "build-apatch/obj/release/loader/armeabi-v7a/stripped/libzygisk.so": 330,
    "build-apatch/obj/release/loader/arm64-v8a/stripped/libzygisk_ptrace.so": 100,
    "build-apatch/obj/release/loader/armeabi-v7a/stripped/libzygisk_ptrace.so": 100,
    "build-apatch/obj/release/zygiskd/arm64-v8a/zygiskd": 60,
    "build-apatch/obj/release/zygiskd/armeabi-v7a/zygiskd": 56,
}


def main(argv):
    roots = [root.rstrip("/\\") for root in argv[1:]]

    failed = False

    for path, limit in sorted(BUDGET_KIB.items()):
        if roots and not any(path.startswith(root + os.sep) or path.startswith(root + "/") for root in roots):
            continue

        if not os.path.exists(path):
            print(f"MISSING                {path}")
            failed = True

            continue

        actual = os.path.getsize(path) // 1024
        over = actual > limit
        failed = failed or over

        print(f"{actual:6} KiB / {limit:6} KiB  {'OVER' if over else 'ok  '}  {path}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
