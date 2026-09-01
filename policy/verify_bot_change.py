#!/usr/bin/env python3
"""Classify a bot-produced working-tree diff without granting an approval."""
import argparse
import fnmatch
import subprocess
import sys
from pathlib import PurePosixPath


# These are cross-repository trust boundaries.  Repositories can add their own
# protected paths, but cannot opt out of these defaults.
BUILTIN_PROTECTED = (
    ".github/**",
    ".router-infra/**",
    "**/ReviewGate*",
    "**/review-gate*",
    "**/source-lock*",
    "**/locked-input*",
)


class NeedsHumanReview(ValueError):
    """A safe stop: the diff must not become a bot proposal."""


def patterns(value):
    return tuple(line.strip() for line in value.splitlines() if line.strip())


def matches(path, pattern):
    return fnmatch.fnmatchcase(path, pattern) or PurePosixPath(path).match(pattern)


def changed_paths():
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-status", "-z", "-M", "-C",
         "--find-copies-harder", "HEAD"],
        check=True, text=False, capture_output=True,
    )
    records = result.stdout.split(b"\0")
    paths = []
    index = 0
    while index < len(records) - 1:
        status = records[index].decode("ascii")
        index += 1
        if not status:
            raise ValueError("invalid Git diff status")
        if index >= len(records):
            raise ValueError("Git diff status has no path")
        path = records[index].decode("utf-8")
        index += 1
        if status[0] in "RC":
            if index >= len(records):
                raise ValueError("Git rename/copy status has no destination path")
            destination = records[index].decode("utf-8")
            index += 1
            raise NeedsHumanReview(
                f"bot proposals may not rename or copy files: {path} -> {destination}"
            )
        if status[0] == "D":
            raise NeedsHumanReview(f"bot proposals may not delete files: {path}")
        paths.append(path)
    return tuple(paths)


def classify(paths, allowed, protected):
    if not paths:
        return False, "no repository changes were produced"
    for path in paths:
        if not any(matches(path, pattern) for pattern in allowed):
            return False, f"changed path is outside allowed-change-paths: {path}"
        if any(matches(path, pattern) for pattern in (*BUILTIN_PROTECTED, *protected)):
            return False, f"changed path requires human review: {path}"
    return True, "all changed paths are eligible for a bot proposal"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowed-change-paths", required=True,
                        help="newline-separated repository-relative globs; inspect staged changes")
    parser.add_argument("--protected-paths", default="",
                        help="newline-separated repository-specific globs")
    args = parser.parse_args()
    allowed, protected = patterns(args.allowed_change_paths), patterns(args.protected_paths)
    if not allowed:
        parser.error("allowed-change-paths must contain at least one path pattern")
    try:
        accepted, reason = classify(changed_paths(), allowed, protected)
    except NeedsHumanReview as error:
        print(f"needs-human-review: {error}")
        return 3
    except (subprocess.CalledProcessError, UnicodeDecodeError, ValueError) as error:
        print(f"needs-human-review: unable to inspect Git diff: {error}", file=sys.stderr)
        return 2
    print(("bot-eligible" if accepted else "needs-human-review") + f": {reason}")
    return 0 if accepted else 3


if __name__ == "__main__":
    sys.exit(main())
