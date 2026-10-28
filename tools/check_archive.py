#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the installable extension and reject local-only release material."""
import argparse
from pathlib import PurePosixPath
from zipfile import ZipFile


def check_archive(path, ghidra_version=None):
    required = {
        "C6000/extension.properties", "C6000/Module.manifest",
        "C6000/lib/C6000.jar", "C6000/LICENSE", "C6000/NOTICE.md",
        "C6000/data/languages/c6000.ldefs", "C6000/data/languages/c6000.opinion",
        *(f"C6000/data/languages/{name}.sla" for name in
          ("c6000_le", "c6000_be", "c6000_le_analysis", "c6000_be_analysis")),
    }
    private = {".git", ".research", "scratch", ".tmp", "__pycache__", ".DS_Store"}
    with ZipFile(path) as archive:
        names = archive.namelist()
        missing = required - set(names)
        if missing:
            raise ValueError("Missing archive members: " + ", ".join(sorted(missing)))
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive members")
        for member in names:
            parts = PurePosixPath(member).parts
            if (not parts or parts[0] != "C6000" or ".." in parts or
                    private.intersection(parts) or member.endswith(".pyc") or
                    member.startswith("C6000/tools/research/")):
                raise ValueError("Unexpected archive member: " + member)
        for member in required:
            if archive.getinfo(member).file_size == 0:
                raise ValueError("Empty archive member: " + member)
        bad = archive.testzip()
        if bad:
            raise ValueError("Archive CRC failed: " + bad)
        properties = dict(line.split("=", 1) for line in
                          archive.read("C6000/extension.properties").decode().splitlines()
                          if "=" in line and not line.startswith("#"))
        if properties.get("name") != "C6000":
            raise ValueError("Incorrect extension name")
        if ghidra_version and properties.get("version") != ghidra_version:
            raise ValueError("Extension compatibility version does not match Ghidra " +
                             ghidra_version)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("--ghidra-version")
    args = parser.parse_args()
    try:
        check_archive(args.archive, args.ghidra_version)
    except (ValueError, OSError) as error:
        parser.exit(1, f"error: {error}\n")
    print("C6000_ARCHIVE_OK " + args.archive)
