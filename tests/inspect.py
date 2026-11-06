import pathlib, re, sys
# Print repr() of lines matching a needle, to see exact backslashes / unicode
for f in sys.argv[2:]:
    for i, line in enumerate(pathlib.Path(f).read_text(encoding="utf-8").splitlines(), 1):
        if sys.argv[1] in line:
            print(f"{f}:{i}: {line.strip()[:220]!r}")
