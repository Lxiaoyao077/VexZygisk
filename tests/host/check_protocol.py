#!/usr/bin/env python3
"""Guards the loader/daemon protocol against one-sided drift.

The loader (loader/src/) and the daemon (zygiskd/src/) each implement their
half of the wire protocol, and merging their socket helpers into one shared
file is deliberately off the table: read_string alone has two intentional
semantics (malloc'd string on the loader, bounded buffer fill on the daemon).
What keeps them honest is this check — it parses both sides' headers and
asserts that the action enum and the socket helper surface stay identical.

Run in CI's host-test job; exits non-zero on the first divergence.
"""

import re
import sys

PATHS = {
    "daemon actions": "zygiskd/src/constants.h",
    "loader actions": "loader/src/include/daemon.h",
    "daemon helpers": "zygiskd/src/utils.h",
    "loader helpers": "loader/src/include/socket_utils.h",
}


def read(path):
    with open(path, encoding="utf-8") as file:
        return file.read()


def enum_members(text, enum_name):
    match = re.search(r"enum\s+" + enum_name + r"\s*\{(.*?)\}", text, re.S)
    if not match:
        raise SystemExit(f"cannot find enum {enum_name}")

    body = re.sub(r"/\*.*?\*/", "", match.group(1), flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)

    members = []
    for item in body.split(","):
        item = item.strip()
        if not item:
            continue

        members.append(item.split("=")[0].strip())

    return members


def helper_names(text):
    """Collects the wire helpers each side declares: the typed read/write
    families plus the fd and string primitives. read_string is excluded on
    purpose — its two signatures are intentional, not drift."""
    names = set()

    for kind in ("write", "read"):
        for type_name in re.findall(r"\b" + kind + r"_func(?:_def)?\(\s*(\w+)\s*\)", text):
            names.add(f"{kind}_{type_name}")

    for helper in ("write_fd", "read_fd", "write_string", "write_loop", "read_loop"):
        if re.search(r"\b" + helper + r"\s*\(", text):
            names.add(helper)

    return names


def main():
    daemon_actions = enum_members(read(PATHS["daemon actions"]), "DaemonSocketAction")
    loader_actions = enum_members(read(PATHS["loader actions"]), "rezygiskd_actions")

    failed = False

    if daemon_actions != loader_actions:
        failed = True

        print("ACTION MISMATCH between the daemon and the loader:")

        for index in range(max(len(daemon_actions), len(loader_actions))):
            daemon = daemon_actions[index] if index < len(daemon_actions) else "(missing)"
            loader = loader_actions[index] if index < len(loader_actions) else "(missing)"

            marker = "  " if daemon == loader else "! "
            print(f"{marker}{index:2}  daemon={daemon:24} loader={loader}")

    daemon_helpers = helper_names(read(PATHS["daemon helpers"]))
    loader_helpers = helper_names(read(PATHS["loader helpers"]))

    if daemon_helpers != loader_helpers:
        failed = True

        print("HELPER MISMATCH between the daemon and the loader:")
        print(f"  daemon only: {sorted(daemon_helpers - loader_helpers)}")
        print(f"  loader only: {sorted(loader_helpers - daemon_helpers)}")

    if not failed:
        print(f"protocol check ok: {len(daemon_actions)} actions, "
              f"{len(daemon_helpers)} shared helpers")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
