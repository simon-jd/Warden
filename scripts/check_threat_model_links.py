#!/usr/bin/env python3
"""Check explicit local Markdown links; never execute targets or fetch URLs.

Supports inline links, reference definitions, ATX heading fragments and duplicate
heading suffixes in this documentation. Fenced code is ignored. This is a small
link check, not a Markdown renderer or an evidence/acceptance verifier.
"""

import argparse
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
from urllib.parse import unquote, urlsplit

DEFAULTS = ("docs/threat-model.md", "docs/soc2-mapping.md", "docs/evidence/README.md")
MAX_BYTES = 2 * 1024 * 1024
INLINE = re.compile(r"!?\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^\s)]+))(?:\s+\"[^\"\n]*\")?\s*\)")
REFERENCE = re.compile(r'^\s{0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|(\S+))')


def limit_resources():
    """Bound this process without raising an inherited tighter ceiling."""
    for kind, maximum in ((resource.RLIMIT_CPU, 20),
                          (resource.RLIMIT_AS, 256 * 1024 * 1024),
                          (resource.RLIMIT_FSIZE, MAX_BYTES)):
        soft, hard = resource.getrlimit(kind)
        cap = maximum if hard == resource.RLIM_INFINITY else min(maximum, hard)
        if soft != resource.RLIM_INFINITY:
            cap = min(cap, soft)
        resource.setrlimit(kind, (cap, cap))
    signal.alarm(45)


def public_file(root, relative):
    """Reject lexical escape and symlinks before opening any target body."""
    if relative.is_absolute():
        raise ValueError("absolute target is outside the repo-local link contract")
    parts = []
    for part in relative.parts:
        if part == "..":
            if not parts:
                raise ValueError("target escapes repository")
            parts.pop()
        elif part != ".":
            if part.startswith("."):
                raise ValueError("private/hidden path is forbidden")
            parts.append(part)
    path = root
    for part in parts:
        path = path / part
        if stat.S_ISLNK(path.lstat().st_mode):
            raise ValueError("symlink target/component is forbidden")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("target is not a regular file")
    return path


def read_text(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError("text target is not a regular file <=2MiB")
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("text target exceeds 2MiB")
    return raw.decode("utf-8")


def prose_lines(body):
    fence = None
    for number, line in enumerate(body.splitlines(), 1):
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is None:
            yield number, line


def fragments(body):
    result = set()
    for _, line in prose_lines(body):
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not heading:
            continue
        slug = re.sub(r"[^\w\- ]", "", heading.group(1).lower()).replace(" ", "-")
        candidate, suffix = slug, 0
        while candidate in result:
            suffix += 1
            candidate = f"{slug}-{suffix}"
        result.add(candidate)
    return result


def check_files(root, sources):
    errors, checked = [], 0
    for source in sources:
        try:
            path = public_file(root, Path(source))
            body = read_text(path)
        except (OSError, ValueError, UnicodeError) as exc:
            errors.append(f"{source}:1: cannot read source: {exc}")
            continue
        for number, line in prose_lines(body):
            matches = list(INLINE.finditer(line))
            definition = REFERENCE.match(line)
            if definition:
                matches.append(definition)
            for match in matches:
                target = match.group(1) or match.group(2)
                try:
                    url = urlsplit(target)
                    if url.scheme in ("https", "http", "mailto"):
                        continue
                    if url.scheme or url.netloc or url.query:
                        raise ValueError("unsupported local URI, authority or query")
                    decoded = unquote(url.path)
                    if "\x00" in decoded or "\\" in decoded:
                        raise ValueError("invalid local path")
                    relative = Path(source).parent / decoded if decoded else Path(source)
                    if Path(decoded).is_absolute():
                        raise ValueError("absolute local target is forbidden")
                    destination = public_file(root, relative)
                    if url.fragment:
                        if destination.suffix.lower() != ".md":
                            raise ValueError("fragments require a Markdown heading target")
                        if unquote(url.fragment) not in fragments(read_text(destination)):
                            raise ValueError(f"missing heading fragment #{url.fragment}")
                    checked += 1
                except (OSError, ValueError, UnicodeError) as exc:
                    errors.append(f"{source}:{number}: {target}: {exc}")
    return errors, checked


def main():
    limit_resources()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", help="repo-relative Markdown sources (defaults to Task17 docs)")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    errors, checked = check_files(root, args.files or DEFAULTS)
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Checked {checked} local links; {len(errors)} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
