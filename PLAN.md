# PLAN

## Contract

```
derx parse FILE    print the DER structure of FILE
derx cert  FILE    print the X.509 certificate fields of FILE
```

`FILE` of `-` reads stdin. Input is DER only; there is no base64 decoder.

`derx parse` prints one line per ASN.1 element, in encoding order, descending
into every constructed element. Each line carries the element's offset in the
file, its nesting depth, the number of header octets, the number of content
octets, whether it is constructed or primitive, its tag, and its value where
the tag has one worth printing.

**That output is specified as being byte-identical to `openssl asn1parse -i -in
FILE -inform DER` for every input that is valid DER.** The column layout, the
tag names, the value formats and the trailing blanks are openssl's, not a
format of our own. Where the two differ, `derx` is wrong by definition.

`derx cert` prints nine `key=value` lines -- version, serial, sigalg, issuer,
notBefore, notAfter, subject, keyalg, keybits -- and then one `ext=` line per
certificate extension. Five of the nine use the spellings
`openssl x509 -noout -serial -issuer -subject -startdate -enddate` already
prints, so those lines are comparable without normalisation. Names follow
RFC 2253, as `openssl x509 -nameopt RFC2253` renders it.

`derx` reads **DER**, not BER. Every place where DER admits one encoding and
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
input is either parsed in agreement with openssl or refused with a message --
never accepted and misread.**

Three halves, and the second is the one that costs the most to get wrong:

1. **No out-of-bounds access, ever.** `hdr()` is the only place with a bounds
   argument and it is given the end of the *enclosing* element, not of the
   file, so an element overrunning its parent is an error at the point of
   decode rather than a read into a sibling. Verified under
   `-fsanitize=address,undefined` across 1524 mutated inputs -- every prefix of
   a certificate, and every single-byte corruption to `00` and `FF` at every
   offset -- with `ASAN_OPTIONS=exitcode=86` so a sanitizer abort cannot be
   mistaken for a clean refusal.
2. **Agreement, not resemblance.** For valid DER, `derx parse` output equals
   `openssl asn1parse -i` byte for byte. Not "looks like", not "contains the
   same facts": equal, as `cmp` sees it. A single differing space anywhere
   fails the suite.
3. **Refusal is loud and distinguishable.** Exit 1 plus a diagnostic, never a
   crash, never a signal, never silently truncated output presented as
   complete. An input `derx` cannot read fully is one it reads not at all.

If any of those three is violated the project has failed, in that order of
severity. A DER reader that misreads quietly is worse than one that cannot
read, because everything downstream of it believes it.

## Oracle

`/usr/bin/openssl` 3.5.7. Ranked by how little of each I control:

1. **The 150 distinct certificates in `/etc/ssl/certs`.** Issued by real CAs
   over twenty-five years, read-only, not mine in any sense. 9,627 elements,
   byte-identical. They carry things no local generator produces: a T61String
   in Entrust's 1999 root, a GeneralizedTime in Certum's 2011 one, OIDs openssl
   itself cannot name, an authority key identifier with a full issuer name and
   serial. This is the group that finds what the fixtures cannot.
2. **`openssl asn1parse -i`, as a diff.** The strongest form an assertion can
   take: there is no expected value, no normalisation and no tolerance, just
   two byte streams that have to be equal.
3. **`openssl x509 -serial -issuer -subject -startdate -enddate`.** Five
   whole-line comparisons with nothing in the middle, because openssl's own
   output prefixes were adopted as the format.
4. **`openssl x509 -ext NAME`**, per extension, and `openssl x509 -text` for
   the four fields with no one-line flag and for the extension name and
   critical-flag sequence. These need a `sed` or an `awk` on the oracle's side,
   which makes them weaker than 2 and 3, so each is guarded by a count: nine
   field lines exactly, and extension agreements in the hundreds.
5. **Objects from openssl's own encoder.** Twenty-five of them: three RSA
   sizes against three digests, three EC curves, Ed25519, a validity past
   2049, all 24 X.520 attribute types, awkward distinguished names, a
   multi-valued RDN, SAN/EKU/basicConstraints, plus a PKCS#10 request, a
   PKCS#1 key, a PKCS#8 PrivateKeyInfo, an EC key and bare EC parameters.
   Weaker than 1 because I chose the arguments.
6. **openssl's acceptance of inputs we refuse.** Nineteen cases where openssl
   reads BER that is not DER. Asserting openssl's exit 0 is what keeps
   "openssl is more permissive here" a measurement rather than a claim.
7. **Hand-built DER.** The weakest of the openssl-backed groups, because I
   wrote the bytes -- but openssl still judges the output, and this is the only
   way to reach a v1 certificate, an unnamed attribute type, a UTCTime at the
   century boundary, a key usage with a nonzero padding bit, or the obsolete
   unique identifiers. Every one of those came from a mutation surviving.
8. **The sanitizers.** Not an oracle about meaning at all -- they have no
   opinion about what the bytes say. They judge the half openssl cannot: that
   we stayed inside the buffer.
9. **Our own mutation sweep.** Fifty-one deliberate defects, fifty killed by a
   named assertion and one provably equivalent. The weakest link, since the
   mutations are mine, but it is what found five dead checks and one real
   off-by-one that 121 green assertions had not.

Nothing in `t/run.sh` checks `derx` against `derx`, and a missing `openssl`
exits 2 rather than reporting skips: with no oracle there is no pass to report.

## Non-goals

- **Cryptography.** No signature verification, no hashing, no key operations.
  This is permanent. The moment `derx` claims a certificate is *valid* it needs
  a constant-time bignum, a trust store policy and a CVE process, and it stops
  being a one-file DER reader. Printing what the bytes say is a complete job.
- **Chain building, validation, expiry, hostname matching, revocation.** Same
  reason.
- **BER.** Indefinite lengths and constructed strings are what DER exists to
  remove; accepting them would make the `D` in the name false. The cost is
  named in the README: a streamed CMS or PKCS#7 blob is unreadable.
- **PEM.** A base64 decoder is twenty lines and would blur the contract, which
  is about DER. `openssl x509 -outform DER` exists, and the test harness uses
  it on 150 files per run.
- **Encoding.** `derx` reads; it does not write DER. A round-trip oracle
  against our own reader would be exactly the kind of self-consistency check
  this project is organised against, and the real oracle for an encoder is
  `openssl asn1parse` accepting our output -- a different project.
- **CRLs, PKCS#7, PKCS#12, OCSP, CSR field printing.** The structural reader
  already handles all of them as DER; naming their fields is scope without an
  invariant.
- **A library.** One program, two subcommands.
- **Printing every extension.** Six are decoded because six are the ones
  openssl renders on a single line, which is what makes a per-extension oracle
  possible. The rest print their name and critical flag, which is checked, and
  `?` for the value, which is honest.
- **An `--lax` or `--ber` flag.** Two modes means two contracts, and the second
  one would have openssl's BER behaviour as its spec, which is a moving target.

## Commit sequence

Every commit builds, verified by checking each one out into a fresh clone,
removing the artifacts so a stale binary cannot fake a pass, and rebuilding.
Every commit after the fifth is green through `cq c`. Granularity is for
`git bisect` and `git revert`; no count is given here because a count in a
file that is itself committed is always one behind.

- [x] `Makefile`, `LICENSE`, `.gitignore`, and `derx.c` reduced to input,
      `hdr()` and the exact asn1parse column layout, one top-level element per
      line, no recursion and no values.
      why: the column format is the oracle. If offset, depth, header length and
      length are not byte-identical then nothing downstream can be compared at
      all, so it is the one piece that cannot be added later. Deriving it from
      the oracle's output rather than from openssl's source is the whole method
      in miniature.
- [x] Recursion into constructed elements, with openssl's own depth limit of
      128 measured rather than assumed.
      why: structure is the main claim and the recursion is where a hostile
      input turns into a stack overflow. Both sides of the 128/129 boundary are
      now the oracle's call, not a guess that happens to be safe.
- [x] Values: BOOLEAN, INTEGER and ENUMERATED, OCTET STRING, the string tags.
      why: the negative-INTEGER magnitude is the only real arithmetic in the
      printer and deserved isolating; it is also where three DER restrictions
      that openssl merely complains about became refusals.
- [x] OBJECT IDENTIFIER: arbitrary-width arcs and the name table.
      why: separable, and the one place a 64-bit accumulator would be silently
      wrong rather than failing. Landing it last among the value types means
      the corpus diff went from "every OBJECT line differs" to zero in one
      commit, which is a clean before and after.
- [x] `t/run.sh`: 121 assertions, the four assertion kinds, and the guards
      against the suite doing nothing.
      why: everything above was judged by eye against openssl until this
      point. The guards -- both programs must have accepted, the oracle must
      have printed something, the corpus must have at least 100 certificates
      and 5000 elements -- are the reason this file is worth more than the
      assertions in it.
- [x] The off-by-one fixture the suite could not see.
      why: a mutation survived 121 green assertions. Kept as its own commit so
      the history records that the sweep found something a complete-looking
      suite had missed.
- [x] `derx cert`, judged by three openssl subcommands, and the hand-built
      certificate.
      why: the certificate reader is a different program from the structural
      reader -- it has field semantics, not just encoding -- so it gets its own
      oracles and its own commit. The hand-built fixture is here because v1
      and unnamed attribute types are unreachable through openssl's generator.
- [x] Twenty-eight mutations against the certificate reader; four survived and
      twenty-two assertions were added.
      why: a green suite proves nothing about the assertions that are not in
      it. Each of the four survivors named a dead check -- the year pivot, the
      key usage padding bits, the unique-identifier skip, and `rd_end()`
      entirely -- and the fixes made `derx cert` as strict as `derx parse`,
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
      and named there rather than rewritten in history.

### Milestone 1 -- close the testing gaps

- [ ] A differential fuzzer: mutate a seed corpus, run both `derx parse` and
      `openssl asn1parse`, and report any input where the exit statuses or the
      outputs disagree, with a shrinker.
      why: the current corruption sweep is 00 and FF at every offset of one
      certificate -- systematic but shallow, and it never produces a
      structurally valid file that is semantically strange. This is the largest
      honest gap in the suite and the one place where the oracle is free:
      openssl is already installed and already the authority, so a fuzzer costs
      nothing but the loop.
- [ ] Record the per-extension agreement counts as exact numbers rather than a
      floor of 400 and a ceiling of 20.
      why: the README names this as a weakness. A change that moved twenty
      values from "agree" to "decline" would pass today. Exact counts mean a
      trust-store update breaks the suite loudly, which is the right failure.
- [ ] Mutation-test `t/run.sh` itself: break the harness rather than the code
      and confirm the breakage is visible.
      why: ten of the eighteen defects recorded across these repositories were
      in a test rig. Six of this one's were. The sweep so far has only
      mutated `derx.c`.

### Milestone 2 -- the extensions that are names only

- [ ] CRL distribution points, authority information access and certificate
      policies.
      why: these three are the ones actually present in the corpus with `?` as
      their value -- 13, 1 and 7 occurrences. openssl prints them on several
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

### Milestone 3 -- beyond the certificate

- [ ] `derx crl FILE`, against `openssl crl -noout -text`.
      why: a CRL is the same AlgorithmIdentifier, Name, Time and extension
      machinery already written, re-assembled -- so it is mostly free, and it
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
      it has a real external check rather than a round trip through our own
      reader. Listed here and not above because it changes what the project is.
- [ ] Grow the OID table from openssl's `objects.txt` at build time.
      why: 69 hand-typed entries is the most fragile thing in the repository,
      and the failure mode is the suite breaking when a new certificate
      appears. Generating the table from openssl's own data would make the
      names the oracle's rather than mine -- but it also introduces a build
      step and a file that is not in this repository, which is why it is last.
