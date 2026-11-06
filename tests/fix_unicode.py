import pathlib
p = pathlib.Path("/home/claude/webinv/src/engine.cs")
s = p.read_text(encoding="utf-8")
ls, ps = chr(0x2028), chr(0x2029)
bad = s.count(ls) + s.count(ps)
bs = chr(92)
old = '[' + bs + 'n' + bs + 'v' + bs + 'f' + bs + 'r' + bs + 'x85' + ls + ps + '])")'
new = '[' + bs + 'n' + bs + 'v' + bs + 'f' + bs + 'r' + bs + 'x85" + "' + bs + bs + '" + "u2028" + "' + bs + bs + '" + "u2029])")'
assert old in s, "pattern not found"
s = s.replace(old, new)
p.write_text(s, encoding="utf-8")
print("replaced; line separators before:", bad, "after:", s.count(ls) + s.count(ps))
# report any remaining non-ASCII in sources
for f in pathlib.Path("/home/claude/webinv/src").iterdir():
    t = f.read_text(encoding="utf-8")
    for i, ch in enumerate(t):
        if ord(ch) > 127:
            line = t.count("\n", 0, i) + 1
            print(f"{f.name}:{line}: U+{ord(ch):04X}")
