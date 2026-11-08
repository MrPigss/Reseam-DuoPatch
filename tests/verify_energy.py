"""Focused JADX-fallback comparison; no DEX parser or Android runtime emulation.
Run: python3 tests/verify_energy.py ORIGINAL_FALLBACK PATCHED_FALLBACK
"""
import re
import sys
from pathlib import Path

before, after = (Path(p).read_text() for p in sys.argv[1:])
insertions = ["r1 = 25", "r5 = 25", "r4 = r4 & (-257(0xfffffffffffffeff, float:NaN))"]
for line in insertions:
    assert after.count(line) == 1, line
    assert line not in before


def normalize_method(source):
    lines = [s.strip() for s in source.splitlines() if s.strip() not in insertions]
    # Resolve every relocated branch to the same instruction ordinal, not label spelling.
    labels = {}
    instructions = []
    for line in lines:
        if re.fullmatch(r"L[0-9a-f]+:", line):
            labels[line[:-1]] = len(instructions)
        else:
            instructions.append(line)
    return [re.sub(r"\bL[0-9a-f]+\b", lambda m: f"target_{labels[m[0]]}", s)
            for s in instructions]


def normalize(source):
    return [normalize_method(part) for part in source.split("\n    public")]


assert normalize(before) == normalize(after), "Unexpected change or branch relocation"
assert after.index("if (r2 != r0)") < after.index("r5 = 25") < after.index("r3.a = r5")
assert after.index("r1 = 25") < after.index("r0.a = r1")

assert after.count("defpackage.nvi.k0(") == 1

# Interpret just the actual synthetic validation/fullness slice of the fallback output.
body = after.split("r3 = this;", 1)[1].split("public EnergyConfig", 1)[0]
lines = [s.strip() for s in body.splitlines()]
labels = {s[:-1]: i for i, s in enumerate(lines) if re.fullmatch(r"L[0-9a-f]+:", s)}
for mask in range(512):
    for maximum in (0, 24, 25, 26, 100):
        for explicit in (0, 1):
            r = {0: 0, 1: 0, 2: 0, 4: mask, 5: -10, 6: maximum, 17: explicit}
            pc = 0
            full = None
            rejected = False
            while pc < len(lines):
                s = lines[pc]
                pc += 1
                if s.startswith("defpackage.nvi.k0("):
                    rejected = True
                    break
                if s == "return":
                    break
                m = re.fullmatch(r"if \(r(\d+) != (r\d+|0)\) goto (L[0-9a-f]+)", s)
                if m:
                    a, b, label = m.groups()
                    if r[int(a)] != (r[int(b[1:])] if b.startswith("r") else 0):
                        pc = labels[label]
                    continue
                if s.startswith("goto "):
                    pc = labels[s[5:]]
                    continue
                m = re.match(r"r(\d+) = (.*)", s)
                if m:
                    dest, value = m.groups()
                    if " & " in value:
                        src, literal = value.split(" & ")
                        number = re.search(r"-?\d+", literal)
                        assert number is not None
                        r[int(dest)] = r[int(src[1:])] & int(number[0])
                    elif re.fullmatch(r"r\d+", value):
                        r[int(dest)] = r.get(int(value[1:]), 0)
                    elif re.fullmatch(r"-?\d+", value):
                        r[int(dest)] = int(value)
                if s == "r3.i = r4":
                    full = bool(r[4])
            assert rejected == (mask & 63 != 63)
            if not rejected:
                assert r[5] == 25 and r[6] == maximum
                assert full == (maximum == 25), (mask, maximum, explicit)
print("PASS: exactly three fallback insertions, all other instructions/branch targets unchanged; 512 masks × 5 maxima × 2 explicit flags")
print("Limit: JADX representation, not raw DEX/register-header or device execution proof")
