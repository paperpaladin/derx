# PLAN

## Contract

```
derx parse FILE    print the DER structure of FILE
derx cert  FILE    print the X.509 certificate fields of FILE
```

`FILE` of `-` reads stdin. Input is DER only. There is no base64 decoder.

`derx parse` prints one line per ASN.1 element, in encoding order, descending
into every constructed element. Each line carries the element's offset in the
file, its nesting depth, the number of header octets, the number of content
octets, whether it is constructed or primitive, its tag, and its value where
the tag has one worth printing.

**That output is specified as being byte-identical to `openssl asn1parse -i -in
FILE -inform DER` for every input that is valid DER.** The column layout, the
tag names, the value formats and the trailing blanks are openssl's, not a
format of our own. Where the two differ, `derx` is wrong by definition.

`derx cert` prints nine `key=value` lines, version, serial, sigalg, issuer,
notBefore, notAfter, subject, keyalg, keybits, and then one `ext=` line per
certificate extension. Five of the nine use the spellings
`openssl x509 -noout -serial -issuer -subject -startdate -enddate` already
prints, so those lines are comparable without normalisation. Names follow
RFC 2253, as `openssl x509 -nameopt RFC2253` renders it.

`derx` reads DER, not BER. Every place where DER admits one encoding and
BER admits several, `derx` takes the DER one and refuses the others, even where
openssl reads them. Those refusals are enumerated in `README.md` and each is
asserted in the suite together with openssl's acceptance.

Exit status is three-valued and the split must never blur: `0` parsed, `1` the
input was refused and a `derx: ` line says why on stderr, `2` `derx` itself was
invoked wrongly and no input was read.

`derx` performs no cryptography. No signature is verified, no hash computed, no
key used. It reports what a certificate says and never whether it is true.

## Hard invariant

**Nothing is ever read outside the bytes that were handed to us, and every
input is either parsed in agreement with openssl or refused with a message,
never accepted and misread.**

Three halves, and the second is the one that costs the most to get wrong:

1. No out-of-bounds access, ever. `hdr()` is the only place with a bounds
   argument and it is given the end of the *enclosing* element, not of the
   file, so an element overrunning its parent is an error at the point of
   decode, not a read into a sibling. Verified under
   `-fsanitize=address,undefined` across 1524 mutated inputs, every prefix of
   a certificate, every single-byte corruption to `00` and `FF` at every
   offset, and 600 fuzzer mutants, with `ASAN_OPTIONS=exitcode=86` so a
   sanitizer abort cannot be mistaken for a clean refusal. `slurp()` reallocs
   the buffer down to the file's exact size for this to mean anything: while
   it over-allocated 64 KiB, a read past the end of a 1 KiB certificate was
   inside a live allocation and ASan saw nothing. `make overread`, a dependency
   of `make test`, is what holds that: it plants the read and fails unless ASan
   reports it. With the `realloc` removed, every other assertion in the suite
   still passes, sanitizers and all.
2. Agreement, not resemblance. For valid DER, `derx parse` output equals
   `openssl asn1parse -i` byte for byte. Not "looks like", not "contains the
   same facts": equal, as `cmp` sees it. A single differing space anywhere
   fails the suite.
3. Refusal is loud and distinguishable. Exit 1 plus a diagnostic, never a
   crash, never a signal, never silently truncated output presented as
   complete. An input `derx` cannot read fully is one it reads not at all.

If any of those three is violated the project has failed, in that order of
severity. A DER reader that misreads quietly is worse than one that cannot
read, because everything downstream of it believes it.

## Oracle

`/usr/bin/openssl` 3.5.7. Ranked by how little of each I control:

1. The 150 distinct certificates in `/etc/ssl/certs`. Issued by real CAs
   over twenty-five years, read-only, not mine in any sense. 9,627 elements,
   byte-identical. They carry things no local generator produces: a T61String
   in Entrust's 1999 root, a GeneralizedTime in Certum's 2011 one, OIDs openssl
   itself cannot name, an authority key identifier with a full issuer name and
   serial. This is the group that finds what the fixtures cannot.
2. `openssl asn1parse -i`, as a diff. The strongest form an assertion can
   take: there is no expected value, no normalisation and no tolerance, just
   two byte streams that have to be equal. `t/fuzz.py` applies the same diff
   to inputs nobody chose, 600 mutants of the corpus per run, of which 372
   are parsed by both programs and compared. It is also how every row of the
   OID name table is read back: `asn1parse -genstr` encodes the row's dotted
   value, asn1parse names it, and the line has to match.
3. `openssl x509 -serial -issuer -subject -startdate -enddate`. Five
   whole-line comparisons with nothing in the middle, because openssl's own
   output prefixes were adopted as the format.
4. `openssl x509 -ext NAME`, per extension, and `openssl x509 -text` for
   the four fields with no one-line flag and for the extension name and
   critical-flag sequence. These need a `sed` or an `awk` on the oracle's side,
   which makes them weaker than 2 and 3, so each is guarded by a count: nine
   field lines exactly, and a floor per extension rather than one total, since
   a total over six extensions cannot tell which of them is being asked about.
   One of the six, `extendedKeyUsage`, turned out to have no trust-store
   coverage at all.
5. Objects from openssl's own encoder. Twenty-five of them: three RSA
   sizes against three digests, three EC curves, Ed25519, a validity past
   2049, all 24 X.520 attribute types, awkward distinguished names, a
   multi-valued RDN, SAN/EKU/basicConstraints, plus a PKCS#10 request, a
   PKCS#1 key, a PKCS#8 PrivateKeyInfo, an EC key and bare EC parameters.
   Weaker than 1 because I chose the arguments.
6. openssl's acceptance of inputs we refuse. Nineteen cases where openssl
   reads BER that is not DER. Asserting openssl's exit 0 is what keeps
   "openssl is more permissive here" a measurement, not a claim.
7. Hand-built DER. The weakest of the openssl-backed groups, because I
   wrote the bytes, but openssl still judges the output, and this is the only
   way to reach a v1 certificate, an unnamed attribute type, a UTCTime at the
   century boundary, a key usage with a nonzero padding bit, or the obsolete
   unique identifiers. Every one of those came from a mutation surviving.
8. The sanitizers. Not an oracle about meaning at all. They have no
   opinion about what the bytes say. They judge the half openssl cannot: that
   we stayed inside the buffer.
9. Our own mutation sweep. Fifty-six deliberate defects, fifty-five killed
   by a named assertion and one provably equivalent. The weakest link, since
   the mutations are mine, but it is what found five dead checks, one real
   off-by-one that 121 green assertions had not, and an aggregate extension
   count that reported a pass over 155 declines.

Nothing in `t/run.sh` checks `derx` against `derx`, and a missing `openssl`
exits 2 instead of reporting skips: with no oracle there is no pass to report.

## Non-goals

- Cryptography. No signature verification, no hashing, no key operations.
  This is permanent. The moment `derx` claims a certificate is *valid* it needs
  a constant-time bignum, a trust store policy and a CVE process, and it stops
  being a one-file DER reader. Printing what the bytes say is a complete job.
- Chain building, validation, expiry, hostname matching, revocation. Same
  reason.
- BER. Indefinite lengths and constructed strings are what DER exists to
  remove. Accepting them would make the `D` in the name false. The cost is
  named in the README: a streamed CMS or PKCS#7 blob is unreadable.
- PEM. A base64 decoder is twenty lines and would blur the contract, which
  is about DER. `openssl x509 -outform DER` exists, and the test harness uses
  it on 150 files per run.
- Encoding. `derx` reads. It does not write DER. A round-trip oracle
  against our own reader would be exactly the kind of self-consistency check
  this project is organised against, and the real oracle for an encoder is
  `openssl asn1parse` accepting our output: a different project.
- CRLs, PKCS#7, PKCS#12, OCSP, CSR field printing. The structural reader
  already handles all of them as DER. Naming their fields is scope without an
  invariant.
- A library. One program, two subcommands.
- Printing every extension. Six are decoded because six are the ones
  openssl renders on a single line, and that is what makes a per-extension oracle
  possible. The rest print their name and critical flag, which is checked, and
  `?` for the value, which is honest.
- An `--lax` or `--ber` flag. Two modes means two contracts, and the second
  one would have openssl's BER behaviour as its spec, a moving target.

## Commit sequence

Every commit builds, verified by checking each one out into a fresh clone,
removing the artifacts so a stale binary cannot fake a pass, and rebuilding.
Every commit after the fifth is green through `cq c`. Granularity is for
`git bisect` and `git revert`. No count is given here because a count in a
file that is itself committed is always one behind.

- [x] `Makefile`, `LICENSE`, `.gitignore`, and `derx.c` reduced to input,
      `hdr()` and the exact asn1parse column layout, one top-level element per
      line, no recursion and no values.
      why: the column format is the oracle. If offset, depth, header length and
      length are not byte-identical then nothing downstream can be compared at
      all, so it is the one piece that cannot be added later. Deriving it from
      the oracle's output, not from openssl's source is the whole method
      in miniature.
- [x] Recursion into constructed elements, with openssl's own depth limit of
      128 measured, not assumed.
      why: structure is the main claim and the recursion is where a hostile
      input turns into a stack overflow. Both sides of the 128/129 boundary are
      now the oracle's call, not a guess that happens to be safe.
- [x] Values: BOOLEAN, INTEGER and ENUMERATED, OCTET STRING, the string tags.
      why: the negative-INTEGER magnitude is the only real arithmetic in the
      printer and deserved isolating; it is also where three DER restrictions
      that openssl merely complains about became refusals.
- [x] OBJECT IDENTIFIER: arbitrary-width arcs and the name table.
      why: separable, and the one place a 64-bit accumulator would be silently
      wrong instead of failing. Landing it last among the value types means
      the corpus diff went from "every OBJECT line differs" to zero in one
      commit, a clean before and after.
- [x] `t/run.sh`: 121 assertions, the four assertion kinds, and the guards
      against the suite doing nothing.
      why: everything above was judged by eye against openssl until this
      point. The guards, both programs must have accepted, the oracle must
      have printed something, the corpus must have at least 100 certificates
      and 5000 elements, are the reason this file is worth more than the
      assertions in it.
- [x] The off-by-one fixture the suite could not see.
      why: a mutation survived 121 green assertions. Kept as its own commit so
      the history records that the sweep found something a complete-looking
      suite had missed.
- [x] `derx cert`, judged by three openssl subcommands, and the hand-built
      certificate.
      why: the certificate reader is a different program from the structural
      reader (it has field semantics, not just encoding) so it gets its own
      oracles and its own commit. The hand-built fixture is here because v1
      and unnamed attribute types are unreachable through openssl's generator.
- [x] Twenty-eight mutations against the certificate reader; four survived and
      twenty-two assertions were added.
      why: a green suite proves nothing about the assertions that are not in
      it. Each of the four survivors named a dead check: the year pivot, the
      key usage padding bits, the unique-identifier skip, and `rd_end()`
      entirely, and the fixes made `derx cert` as strict as `derx parse`,
      which it had quietly not been.
- [x] The command line and stdin.
      why: `FILE` of `-` was in the usage line and in the contract and nothing
      ran it, and the three-valued exit status that every reject assertion
      leans on had never been pinned down. Found a real bug: a typo in the
      subcommand reported a file error with status 1.
- [x] `README.md`, then `PLAN.md`, as separate commits.
      why: the transcript and the "what does not work" list are a different
      artifact from the contract and the forward plan, and someone reverting
      one rarely wants to revert the other. Also: `cq c` stages the whole
      working tree, so writing both files and then calling it twice produces
      one commit and a "nothing to commit". Staged by hand instead.
- [x] Correct the mutation counts, which commit 08 got wrong in two ways.
      why: it claimed twenty-eight mutations where twenty-six applied and four
      survivors where six did, having counted two of them as "changes the
      sweep forced" instead. A count that flatters the work is the same defect
      as a test that passes by doing nothing, so it is corrected in the README
      and named there, not rewritten in history.

### Milestone 1: close the testing gaps

- [x] A differential fuzzer: mutate a seed corpus, run both `derx parse` and
      `openssl asn1parse`, and report any input where the exit statuses or the
      outputs disagree, with a shrinker.
      done: `t/fuzz.py`, 236 lines, eight mutators, five of them blind byte
      edits and three that keep the framing intact so the mutant is valid DER
      saying something strange. Those three are what makes the run
      non-vacuous: at the seed `make test` uses, 372 of 600 mutants are
      parsed by both programs and compared, and that floor is asserted, since
      "0 differences" over inputs nobody could parse has tested nothing.
      Mutant i is a pure function of (seed, i) with no wall clock anywhere,
      every failure is saved as a file and shrunk, and the suite checks the
      reproducibility claim by digest rather than by effect. Four outcomes
      counted apart: agreement, mismatch, derx-refuses-what-openssl-accepts,
      and both refusing. Over 10,000 mutants at three seeds: 6,390
      comparisons, 0 mismatches, 0 crashes, and 30 files where openssl names
      an OID derx prints in dotted form, which is the one wrong answer it
      found and is counted on its own line.
      Two defects found. `slurp()` over-allocated by 64 KiB, so `make
      test-asan` could not see a read past the end of the file at all: the
      planted missing bounds check produced zero ASan errors in 600 mutants
      and 33 files accepted that openssl refused. After the realloc-down fix
      the same plant produces 31 ASan aborts. And the first version of the
      fuzzer's own determinism assertion passed with `--seed` ignored,
      because the two logs it compared differ on the line that echoes the
      seed.
      why: the current corruption sweep is 00 and FF at every offset of one
      certificate, systematic but shallow, and it never produces a
      structurally valid file that is semantically strange. This is the largest
      honest gap in the suite and the one place where the oracle is free:
      openssl is already installed and already the authority, so a fuzzer costs
      nothing but the loop.
- [x] Record the per-extension agreement counts as exact numbers, not a
      floor of 400 and a ceiling of 20.
      done: six extensions counted apart, printed, each with its own floor.
      The trust store yields 150, 147, 0, 149, 29 and 2 agreements and 0, 0,
      0, 0, 5 and 1 declines; the fixtures yield 16, 6, 1, 16, 16 and 1, and
      those six are asserted as exact equalities, since `t/run.sh` builds
      those inputs and nothing outside the repository can move them. The
      trust-store floors are fractions of the store's size rather than the
      measured numbers, because the group above deliberately accepts as few as
      100 certificates and an exact 150 would call a thinned store a broken
      derx. Declines are held at exactly zero for the four extensions with no
      multi-line form, which the aggregate ceiling of 20 could not say:
      fourteen keyUsage values turning into "?" passed it.
      What the count found: `extendedKeyUsage` agrees 0 times across the whole
      trust store, because a CA root does not carry one, and its entire
      coverage anywhere in the suite is the one generated leaf fixture. The
      aggregate 477 said nothing about that and could not have. Deleting that
      fixture left the old assertion green.
      Five mutations, all killed, three of them passed by the suite as it
      stood. One found a defect in the replacement: with the thresholds moved
      out, the aggregate line was left printing "ok cert extension values:
      328 agree, 155 declined", a pass announcing a number that should have
      failed.
      why: the README named this as a weakness. A change that moved twenty
      values from "agree" to "decline" would have passed.
- [x] A `make overread` gate on `slurp()`, run by `make test`.
      done: `-DDERX_OVERREAD` compiles a read of `b[n]` and the target fails
      unless ASan reports a heap-buffer-overflow and the process exits 86,
      which derx itself never produces. Watched to go red: with the `realloc`
      down to the exact file size removed, `make test` and `make test-asan`
      both report 289 passed, 0 failed and the gate is the only thing that
      fails. It builds in a fresh `mktemp -d` and leaves nothing behind.
      The whole file was swept rather than the one function. There is exactly
      one heap allocation in `derx.c` and it is the one already fixed; `.data`
      and `.bss` are zero bytes, so the static-storage variant cannot occur
      here; the ten stack arrays are each bounded by a guard that calls
      `die()`, and a planted read past one is reported as a
      stack-buffer-overflow. A null result, measured.
      why: the fix landed on 18 October with nothing checking it, and two
      repositories in this collection had this target and never ran it. A
      sanitizer gate nobody has watched fail is a gate whose reach is a guess.
- [x] Drive every row of the OID name table through both programs, instead
      of waiting for an input to carry the OID.
      done: 69 rows read out of `derx.c` by the harness, each encoded with
      `openssl asn1parse -genstr OID:<dotted>` and diffed against
      `asn1parse`. 69 new assertions and 69 more elements, all agreeing, so
      the table held: what did not hold was the claim in `derx.c` that every
      row was verified by diff. 14 rows are carried by nothing in
      `/etc/ssl/certs`, nothing openssl's generator emits and no fixture, so
      they had been typed and read back by nothing: `rsassaPss`,
      `ecdsa-with-SHA1`, `ED448`, seven extension names and four of the seven
      extended key usage purposes. Measured by collecting every OBJECT name
      the oracle prints over every input the suite builds and subtracting it
      from the table.
      Four mutations, all killed. Misspelling `Time Stamping` and changing
      `ED448`'s dotted value both leave the rest of the suite green and fail
      only their own row. Breaking the `sed` that reads the rows drops the
      group's 69 assertions, and the row count catches it; breaking the `awk`
      range leaves both counts at 0 and agreeing, and the floor of 69 catches
      that.
      why: `vtparse` enumerated 3584 table entries without driving the parser
      with any of them, so a cell right in the table and wrong in the code
      read as working. This is the same shape in the other direction, and the
      14 unexercised rows were the measure of it.
- [x] Mutation-test `t/run.sh` itself: break the harness, not the code
      and confirm the breakage is visible.
      done: 20 mutations over the whole file, one at a time, each run against
      an unmodified `derx`. Ten of the twenty left the suite reporting 289
      passed, 0 failed, the worst being the `cmp` in `agree()` replaced by
      `true`: one word, and the diff this project is built on stopped running
      while 163 assertions reported passes.
      Twelve are killed now, by eleven assertions that run the harness
      against an input or a stub program chosen to make it fail and require
      it to fail, and by a count of the assertions the file ran compared
      against a literal. Each of the eleven was watched to go red by deleting
      the check it covers. The three stub guards exist because three checks
      are about how the program under test behaves rather than about any
      input, so no file can falsify them: that a refusal carries a
      diagnostic, that exit 1 and exit 2 stay apart, and that a status above
      2 is a defect rather than a refusal.
      Eight survive and the README names them. Three are `agree()`'s own
      guards taken one at a time, each masked by the other two, together
      closing one hole that the empty file is the only input able to reach,
      since openssl prints "Error in encoding" on stdout for most of what it
      refuses. Five are floors and ceilings weakened, which the run that
      passes them cannot see; all five print their measured value beside the
      floor, which is the only defence available from inside.
      why: most of the defects recorded across these repositories were in a
      test rig. Ten of this one's were, and the sweep found a eleventh and a
      twelfth: an oracle that can be disconnected in silence, and an element
      count that can stop counting.
- [ ] Size `print_name()`'s attribute array to what was actually decoded,
      behind a build flag, with the suite run both ways.
      why: `Atv a[256]` holds at most five attributes for anything here, and a
      planted read at `a[na]` produces no diagnostic from ASan or UBSan and
      exits 0, because it is inside the array. This is the one place in
      `derx.c` that no allocation size reaches and the only survivor of the
      buffer sweep. Not a live defect: every write is guarded by
      `na == MAXATV` and the printing loop runs from `na - 1` down. It needs a
      counting pass over the attributes before the array exists, which is the
      `shortcut:` comment's own upgrade path, and `jsonc` has the pattern for
      the flag and the two runs.

### Milestone 2: the extensions that are names only

- [ ] CRL distribution points, authority information access and certificate
      policies.
      why: these three are the ones actually present in the corpus with `?` as
      their value: 13, 1 and 7 occurrences. openssl prints them on several
      lines, so this needs the `ext=` format to grow a multi-line form, which
      is a change to the output contract and therefore wants its own commit.
- [ ] The full authority key identifier, with `authorityCertIssuer` and
      `authorityCertSerialNumber`.
      why: 5 of the 150 certificates here carry one and `derx` declines all
      five. It also needs the GeneralName renderer that subject alternative
      name already has, so it is cheap once the multi-line form exists.
- [ ] The remaining five GeneralName kinds, starting with `directoryName`.
      why: one corpus certificate has a `DirName` in its subjectAltName and
      that makes the whole value decline. `directoryName` reuses the existing
      distinguished-name renderer; the other four do not and may stay out.
- [ ] Name constraints, policy constraints, inhibit anyPolicy, private key
      usage period.
      why: all four are short and all four have a single-line openssl
      rendering, so each is an afternoon with an oracle already in place.

### Milestone 3: beyond the certificate

- [ ] `derx crl FILE`, against `openssl crl -noout -text`.
      why: a CRL is the same AlgorithmIdentifier, Name, Time and extension
      machinery already written, re-assembled, so it is mostly free, and it
      doubles the structural coverage of those pieces against a different
      openssl subcommand. The oracle has to come first: `openssl ca` needs
      setting up to generate one, and there is no CRL on this machine.
- [ ] RSASSA-PSS signature algorithm parameters.
      why: the README names this as both unimplemented and untested. It is the
      one signature algorithm whose parameters carry information, and openssl's
      `-text` spells out the hash, the MGF and the salt length, so the oracle
      is there the moment a fixture exists.
- [ ] A `--der` output mode that re-encodes what was parsed, with `openssl
      asn1parse` on the result as the oracle and byte-identity with the input
      as the invariant.
      why: this is the smallest step that makes `derx` an encoder as well, and
      it has a real external check, not a round trip through our own
      reader. Listed here and not above because it changes what the project is.
- [ ] Grow the OID table from openssl's `objects.txt` at build time.
      why: 69 hand-typed entries is the most fragile thing in the repository,
      and the failure mode is the suite breaking when a new certificate
      appears. Generating the table from openssl's own data would make the
      names the oracle's, not mine, but it also introduces a build
      step and a file that is not in this repository, so it comes last.
