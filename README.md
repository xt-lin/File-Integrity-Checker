#!/usr/bin/env python3
"""
File Integrity Checker
------------------------
Detects unauthorized or accidental changes to files by comparing their
cryptographic hashes (SHA-256) against a previously saved baseline.

Usage:
    python file_integrity_checker.py init  <directory> [--baseline FILE]
    python file_integrity_checker.py check <directory> [--baseline FILE] [--log FILE]

Example:
    python file_integrity_checker.py init  ./my_project
    python file_integrity_checker.py check ./my_project
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime

DEFAULT_BASELINE = "baseline.json"
DEFAULT_LOG = "integrity_log.txt"
HASH_ALGO = "sha256"
CHUNK_SIZE = 65536  # 64 KB, read in chunks so large files don't blow up memory


def compute_hash(filepath, algo=HASH_ALGO):
    """Return the hex digest of a file's contents, or None if unreadable."""
    hasher = hashlib.new(algo)
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
    except (PermissionError, FileNotFoundError, OSError):
        return None
    return hasher.hexdigest()


def scan_directory(directory):
    """Walk a directory and return {relative_path: hash} for every file."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for name in files:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, directory)
            digest = compute_hash(full_path)
            if digest:
                file_hashes[rel_path] = digest
    return file_hashes


def save_baseline(file_hashes, baseline_path, directory):
    data = {
        "directory": os.path.abspath(directory),
        "algorithm": HASH_ALGO,
        "created": datetime.now().isoformat(timespec="seconds"),
        "files": file_hashes,
    }
    with open(baseline_path, "w") as f:
        json.dump(data, f, indent=2)


def load_baseline(baseline_path):
    if not os.path.exists(baseline_path):
        print(f"Error: baseline file '{baseline_path}' not found. Run 'init' first.")
        sys.exit(1)
    with open(baseline_path, "r") as f:
        return json.load(f)


def cmd_init(args):
    if not os.path.isdir(args.directory):
        print(f"Error: '{args.directory}' is not a valid directory.")
        sys.exit(1)
    print(f"Scanning '{args.directory}' ...")
    file_hashes = scan_directory(args.directory)
    save_baseline(file_hashes, args.baseline, args.directory)
    print(f"Baseline created: {len(file_hashes)} file(s) recorded in '{args.baseline}'.")


def cmd_check(args):
    baseline = load_baseline(args.baseline)
    old_hashes = baseline["files"]

    print(f"Scanning '{args.directory}' ...")
    new_hashes = scan_directory(args.directory)

    modified, added, deleted, unchanged = [], [], [], []

    for path, old_hash in old_hashes.items():
        if path not in new_hashes:
            deleted.append(path)
        elif new_hashes[path] != old_hash:
            modified.append(path)
        else:
            unchanged.append(path)

    for path in new_hashes:
        if path not in old_hashes:
            added.append(path)

    lines = []
    lines.append(f"\n=== File Integrity Report ({datetime.now().isoformat(timespec='seconds')}) ===")
    lines.append(f"Directory checked : {os.path.abspath(args.directory)}")
    lines.append(f"Baseline file     : {args.baseline}")
    lines.append(f"Unchanged files   : {len(unchanged)}")

    if modified:
        lines.append(f"\n[MODIFIED] {len(modified)} file(s):")
        lines += [f"  - {p}" for p in modified]
    if added:
        lines.append(f"\n[ADDED] {len(added)} new file(s):")
        lines += [f"  - {p}" for p in added]
    if deleted:
        lines.append(f"\n[DELETED] {len(deleted)} file(s):")
        lines += [f"  - {p}" for p in deleted]

    if not (modified or added or deleted):
        lines.append("\nNo changes detected. All files match the baseline.")
    else:
        lines.append(f"\nTotal changes detected: {len(modified) + len(added) + len(deleted)}")

    report_text = "\n".join(lines)
    print(report_text)

    with open(args.log, "a") as f:
        f.write(report_text + "\n")
    print(f"\nReport appended to '{args.log}'.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="File Integrity Checker - detect file changes using SHA-256 hashing."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a baseline snapshot of a directory.")
    init_parser.add_argument("directory", help="Directory to scan.")
    init_parser.add_argument("--baseline", default=DEFAULT_BASELINE, help="Path to save baseline JSON.")
    init_parser.set_defaults(func=cmd_init)

    check_parser = subparsers.add_parser("check", help="Compare current directory state to the baseline.")
    check_parser.add_argument("directory", help="Directory to scan.")
    check_parser.add_argument("--baseline", default=DEFAULT_BASELINE, help="Path to baseline JSON.")
    check_parser.add_argument("--log", default=DEFAULT_LOG, help="Path to append the report to.")
    check_parser.set_defaults(func=cmd_check)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
    
