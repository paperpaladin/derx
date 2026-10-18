#!/usr/bin/env python3
"""Differential fuzzer for `derx parse` against `openssl asn1parse`.

Mutate DER files from a seed corpus and run both programs over every mutant.
openssl decides; nothing here is an expected value written by hand.

Every mutant is a pure function of (seed, index), so a failure is reproduced
by `--seed S --start I --count 1` and the bytes are written out as well.
There is no wall clock anywhere in this file.

Five outcomes, counted apart because merging any two of them hides a defect:

  agree     both exited 0 and printed the same bytes. This is the only
            outcome that compared anything.
  mismatch  both exited 0 and the output differs. derx is wrong by
            definition: the contract says openssl's bytes are the spec.
  oidgap    both exited 0 and the only difference is that openssl has a
            name for an OID derx prints in dotted form. A wrong answer, and
            kept out of the mismatch count only because it is one known
            missing table (PLAN.md: grow the OID table from objects.txt).
            The test is narrow: every differing line must be an OBJECT line
            identical in every other field, with derx's value purely
            numeric and openssl's not. A different name, or different
            numbers, is a mismatch.
  refusal   derx exited 1 and openssl exited 0. derx reads DER, openssl
            reads BER, so this is expected and is NOT a defect. It is never
            added to the mismatch count.
  rejected  both refused. Nothing was compared. A run that is all rejections
            has tested nothing, which is why --min-compared exists.

Plus three that fail the run: derx exiting above 1 on a parse (a crash, or a
usage error on an input that is merely malformed), derx exiting 1 with no
`derx: ` line on stderr, and derx accepting an input openssl refuses, which
is the wrong direction for a reader of a subset of BER.

usage: t/fuzz.py --seed N --count N [options] CORPUSFILE...
"""

import argparse
import hashlib
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# a tolerant DER scanner, used only to aim the mutations
# ---------------------------------------------------------------------------
# This is not derx's parser and does not judge anything: it locates the
# tag-length-value boundaries so a mutation can hit a tag byte or a content
# byte on purpose. Where the bytes stop making sense it simply stops walking.
#
# shortcut: single-byte tags and definite lengths only; a high-tag-number or
# indefinite-length element ends the walk of that subtree. Those encodings are
# rare in the corpus and the blind byte mutators still reach them. Upgrade
# path is to decode the full tag and length here.


def scan(buf, start, end, depth, out):
    i = start
    while i < end:
        off = i
        t = buf[i]
        if t & 0x1F == 0x1F:
            return
        i += 1
        if i >= end:
            return
        n = buf[i]
        i += 1
        if n == 0x80:
            return
        if n & 0x80:
            k = n & 0x7F
            if k == 0 or k > 4 or i + k > end:
                return
            clen = int.from_bytes(buf[i:i + k], "big")
            i += k
        else:
            clen = n
        if clen > end - i:
            return
        cons = bool(t & 0x20)
        out.append({"off": off, "hlen": i - off, "clen": clen,
                    "cons": cons, "depth": depth})
        if cons:
            scan(buf, i, i + clen, depth + 1, out)
        i += clen


def elements(buf):
    out = []
    try:
        scan(buf, 0, len(buf), 0, out)
    except RecursionError:
        pass
    return out


def children(els, parent):
    """Direct children of parent, in encoding order."""
    inner_end = parent["off"] + parent["hlen"] + parent["clen"]
    return [e for e in els
            if e["depth"] == parent["depth"] + 1
            and parent["off"] < e["off"] < inner_end]


# ---------------------------------------------------------------------------
# the mutators
# ---------------------------------------------------------------------------
# The first four are blind and mostly produce files both programs refuse.
# The last three are structure-aware and keep the file's framing intact, so
# the result is usually a valid DER file that says something strange. Those
# are the ones that reach a comparison, which is the whole point: a fuzzer
# whose every mutant is rejected before parsing has compared nothing.


def m_byte(rng, buf, _corpus):
    b = bytearray(buf)
    b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b)


def m_burst(rng, buf, _corpus):
    b = bytearray(buf)
    for _ in range(rng.randint(2, 8)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b)


def m_truncate(rng, buf, _corpus):
    return buf[:rng.randrange(1, len(buf))]


def m_append(rng, buf, _corpus):
    return buf + bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))


def m_splice(rng, buf, corpus):
    other = corpus[rng.randrange(len(corpus))]
    return buf[:rng.randrange(1, len(buf))] + other[rng.randrange(len(other)):]


def m_tag(rng, buf, _corpus):
    """Retag an element. Length and nesting are untouched, so the file stays
    structurally valid and the value is now printed by a different rule."""
    els = elements(buf)
    if not els:
        return None
    e = els[rng.randrange(len(els))]
    b = bytearray(buf)
    old = b[e["off"]]
    b[e["off"]] = (old & 0xE0) | rng.randint(1, 30)
    if b[e["off"]] == old:
        return None
    return bytes(b)


def m_content(rng, buf, _corpus):
    """Change one byte inside a primitive element's content. Framing is
    untouched: this reaches the value formatters, not the parser."""
    prim = [e for e in elements(buf) if not e["cons"] and e["clen"] > 0]
    if not prim:
        return None
    e = prim[rng.randrange(len(prim))]
    b = bytearray(buf)
    b[e["off"] + e["hlen"] + rng.randrange(e["clen"])] = rng.randrange(256)
    return bytes(b)


def m_swap(rng, buf, _corpus):
    """Swap two siblings. Concatenation length is unchanged, so every
    enclosing length stays correct and only the order is strange."""
    els = elements(buf)
    rng.shuffle(els)
    for p in els:
        if not p["cons"]:
            continue
        kids = children(els, p)
        if len(kids) < 2:
            continue
        kids.sort(key=lambda e: e["off"])
        a, c = sorted(rng.sample(range(len(kids)), 2))
        ka, kc = kids[a], kids[c]
        sa, ea = ka["off"], ka["off"] + ka["hlen"] + ka["clen"]
        sc, ec = kc["off"], kc["off"] + kc["hlen"] + kc["clen"]
        return buf[:sa] + buf[sc:ec] + buf[ea:sc] + buf[sa:ea] + buf[ec:]
    return None


MUTATORS = [m_byte, m_burst, m_truncate, m_append, m_splice,
            m_tag, m_content, m_swap]
# The structure-aware three are drawn more often, because a blind byte in a
# length field is nearly always refused by both and so compares nothing.
WEIGHTS = [2, 2, 1, 1, 1, 4, 5, 3]


def mutate(rng, corpus):
    buf = corpus[rng.randrange(len(corpus))]
    for _ in range(8):
        m = rng.choices(MUTATORS, WEIGHTS)[0]
        out = m(rng, buf, corpus)
        if out:
            return buf, out, m.__name__[2:]
    return buf, m_byte(rng, buf, corpus), "byte"


# ---------------------------------------------------------------------------
# the comparison
# ---------------------------------------------------------------------------

# Outcomes that fail the run. "refusal" is not here: derx reads DER and
# openssl reads BER, so derx refusing alone is the designed divergence.
# "oidgap" is not here either, and that is a judgement call recorded in
# README.md, not a silent one: it is counted and printed on its own line.
FAILING = ("mismatch", "crash", "nodiag", "laxity")


class Runner:
    def __init__(self, derx, workdir):
        self.derx = derx
        self.path = os.path.join(workdir, "mutant.der")
        self.calls = 0

    def classify(self, data):
        """Returns (category, detail). The category names are the counters."""
        self.calls += 1
        with open(self.path, "wb") as f:
            f.write(data)
        d = subprocess.run([self.derx, "parse", self.path],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o = subprocess.run(["openssl", "asn1parse", "-i", "-in", self.path,
                            "-inform", "DER"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if d.returncode > 1:
            return "crash", "derx exited %d" % d.returncode
        if d.returncode == 1 and not d.stderr.startswith(b"derx: "):
            return "nodiag", "exit 1 with no 'derx: ' line: %r" % d.stderr[:80]
        if d.returncode == 0 and o.returncode == 0:
            if d.stdout == o.stdout:
                return "agree", ""
            if oid_name_only(o.stdout, d.stdout):
                return "oidgap", diff(o.stdout, d.stdout)
            return "mismatch", diff(o.stdout, d.stdout)
        if d.returncode == 1 and o.returncode == 0:
            return "refusal", d.stderr.decode("utf-8", "replace").strip()
        if d.returncode == 0 and o.returncode != 0:
            return "laxity", "openssl exited %d" % o.returncode
        return "rejected", ""


DOTTED = re.compile(rb"[0-9]+(\.[0-9]+)+\Z")


def split_oid(line):
    """('  37:d=5 ... OBJECT            ', b'2.5.4.30') or None."""
    k = line.find(b"OBJECT")
    if k < 0:
        return None
    j = line.find(b":", k)
    if j < 0:
        return None
    return line[:j], line[j + 1:]


def oid_name_only(want, got):
    """True when every difference is openssl naming an OID derx did not."""
    w, g = want.split(b"\n"), got.split(b"\n")
    if len(w) != len(g):
        return False
    seen = False
    for a, b in zip(w, g):
        if a == b:
            continue
        pa, pb = split_oid(a), split_oid(b)
        if pa is None or pb is None or pa[0] != pb[0]:
            return False
        if not DOTTED.match(pb[1]) or DOTTED.match(pa[1]):
            return False
        seen = True
    return seen


def diff(want, got):
    w, g = want.split(b"\n"), got.split(b"\n")
    for i in range(max(len(w), len(g))):
        a = w[i] if i < len(w) else b"<no line>"
        b = g[i] if i < len(g) else b"<no line>"
        if a != b:
            return ("line %d\n        openssl: %s\n        derx:    %s"
                    % (i + 1, a.decode("utf-8", "replace"),
                       b.decode("utf-8", "replace")))
    return "identical lines, trailing byte differs"


# ---------------------------------------------------------------------------
# the shrinker
# ---------------------------------------------------------------------------
# Keeps the category, not the exact diagnostic: a smaller input that fails the
# same way is the useful artifact. Budgeted, because every probe is two
# process spawns.

def shrink(runner, data, category, budget=400):
    cur = data
    spent = [0]

    def still(cand):
        if not cand or spent[0] >= budget:
            return False
        spent[0] += 1
        return runner.classify(bytes(cand))[0] == category

    n = max(1, len(cur) // 2)
    while n >= 1:
        i = 0
        while i < len(cur):
            cand = cur[:i] + cur[i + n:]
            if still(cand):
                cur = cand
            else:
                i += n
        if spent[0] >= budget:
            break
        n //= 2
    return cur


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", nargs="+")
    ap.add_argument("--derx", default="./derx")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--min-compared", type=int, default=0,
                    help="fail the run if fewer mutants than this reached a "
                         "comparison; guards against a vacuous green")
    ap.add_argument("--save", default=None,
                    help="directory for failing inputs (default t/fuzz-fail)")
    ap.add_argument("--shrink", type=int, default=3,
                    help="shrink only the first N failures; the rest are "
                         "saved whole. Every shrink probe is two more "
                         "process spawns and under the sanitizers that adds "
                         "up faster than it pays")
    ap.add_argument("--digest", action="store_true",
                    help="print one line per mutant, index and SHA-256, and "
                         "run neither program. This is how the suite checks "
                         "that mutant i is the same bytes whether it was "
                         "reached in a long run or by --start i --count 1, "
                         "which is what makes a saved failure replayable")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    corpus = []
    for p in args.corpus:
        with open(p, "rb") as f:
            b = f.read()
        if len(b) > 1:
            corpus.append(b)
    if not corpus:
        print("fuzz: empty corpus, nothing to mutate", file=sys.stderr)
        return 2
    corpus.sort()           # argv order is a glob's order; this is not.

    if args.digest:
        for i in range(args.start, args.start + args.count):
            rng = random.Random("%d:%d" % (args.seed, i))
            _, data, kind = mutate(rng, corpus)
            print("%d %s %s" % (i, kind, hashlib.sha256(data).hexdigest()))
        return 0

    here = os.path.dirname(os.path.abspath(__file__))
    save = args.save or os.path.join(here, "fuzz-fail")
    # Per run, inside the repo: t/tmp is a fixed path the suite owns, and
    # /tmp is shared between jobs and does not survive a reboot.
    work = tempfile.mkdtemp(prefix="fuzz.", dir=here)
    runner = Runner(args.derx, work)
    counts = {k: 0 for k in ("agree", "mismatch", "oidgap", "refusal",
                             "rejected", "laxity", "crash", "nodiag")}
    bykind = {}
    reasons = {}
    failures = 0

    try:
        for i in range(args.start, args.start + args.count):
            rng = random.Random("%d:%d" % (args.seed, i))
            _, data, kind = mutate(rng, corpus)
            cat, detail = runner.classify(data)
            counts[cat] += 1
            k = bykind.setdefault(kind, {"n": 0, "agree": 0})
            k["n"] += 1
            if cat == "agree":
                k["agree"] += 1
            if cat == "refusal":
                # Grouped with the numbers blanked, because the same rule
                # fires at a different offset every time. This is the list
                # of DER rules the run actually exercised: a refusal nobody
                # can name is how a parser bug hides as strictness.
                r = re.sub(r"[0-9]+", "#", detail)
                reasons[r] = reasons.get(r, 0) + 1
            if cat not in FAILING:
                continue
            failures += 1
            os.makedirs(save, exist_ok=True)
            stem = os.path.join(save, "s%d-i%d" % (args.seed, i))
            with open(stem + ".der", "wb") as f:
                f.write(data)
            if failures <= args.shrink:
                small = shrink(runner, data, cat)
                with open(stem + ".min.der", "wb") as f:
                    f.write(small)
                print("FAIL %s  mutator=%s  %d bytes -> %d shrunk"
                      % (cat, kind, len(data), len(small)))
            else:
                print("FAIL %s  mutator=%s  %d bytes, not shrunk"
                      % (cat, kind, len(data)))
            print("      %s" % detail)
            print("      reproduce: %s --seed %d --start %d --count 1 CORPUS"
                  % (sys.argv[0], args.seed, i))
            print("      saved:     %s.der" % stem)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    n = sum(counts.values())
    if not args.quiet:
        print("fuzz: seed %d, %d mutants from %d corpus files"
              % (args.seed, n, len(corpus)))
        for kind in sorted(bykind):
            k = bykind[kind]
            print("      %-9s %4d mutants, %4d reached a comparison"
                  % (kind, k["n"], k["agree"]))
        for r in sorted(reasons, key=lambda x: -reasons[x]):
            print("      refused %4d  %s" % (reasons[r], r))
    print("fuzz: %d compared and agreed, %d mismatched, %d differed only in "
          "an OID name, %d refused by derx alone, %d refused by both, "
          "%d accepted by derx alone, %d crashed, %d undiagnosed"
          % (counts["agree"], counts["mismatch"], counts["oidgap"],
             counts["refusal"], counts["rejected"], counts["laxity"],
             counts["crash"], counts["nodiag"]))

    if counts["agree"] < args.min_compared:
        print("fuzz: only %d mutants reached a comparison, wanted %d: this "
              "run proved nothing" % (counts["agree"], args.min_compared))
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
