# pwdemo

An educational demonstration of why unsalted, fast password hashes are
crackable, and why modern salted hashing resists the same attacks —
using **only synthetic passwords** bundled with this project, and
**bounded searches** that finish in about a second.

## Scope — please read before anything else

- **Every password anywhere in this project is fake.** `pwdemo/synthetic_data.py`
  is the single source of every password used — a generated wordlist of
  invented weak passwords, and five named target scenarios. None of it
  comes from a real breach dataset, and nothing here has ever been a
  real credential.
- **Every search is bounded.** The dictionary is ~576 words. The
  brute-force keyspace is capped at lowercase+digits, length ≤ 4
  (≈1.73 million combinations) — and `bruteforce_attack.py` enforces a
  hard `SAFETY_MAX_KEYSPACE` ceiling in code, not just via chosen
  defaults, so no caller can accidentally request an unbounded search.
- **This is a teaching tool, not a cracking tool.** The CLI only ever
  runs against the bundled synthetic scenarios — there is no flag or
  interface anywhere for pointing any of this at a real password or a
  real hash. The underlying functions (`dictionary_attack_unsalted`,
  `brute_force_unsalted`, etc.) are, unavoidably, generic implementations
  of textbook algorithms — that's what makes them a useful demonstration
  — but this project's own scripts and CLI never call them with
  anything but the synthetic data in `synthetic_data.py`.

## What this demonstrates

1. **Weak hashing is fast and unsalted** → the same password always
   produces the same hash, and hashing is cheap, so an attacker can
   precompute once and reuse the result, or just try millions of
   guesses per second.
2. **Two ways to exploit that**: a live guessing attack (dictionary or
   brute-force) computed on the spot, or a **precomputed** attack
   (a lookup table or a rainbow table) where the expensive part was
   already done ahead of time.
3. **A simple lookup table vs. a real rainbow table** — both are
   precomputation attacks, but they make a different space/time
   tradeoff (see below), and this project implements *both*, not just
   one described as a stand-in for the other.
4. **Modern salted hashing (PBKDF2)** defeats precomputation attacks
   entirely (a table built for unsalted hashes can't match a salted one
   at all) and makes live guessing attacks dramatically slower per
   guess — but does **not** make a weak, in-dictionary password safe.
   That distinction is the main thing this project is trying to teach
   accurately, rather than the common oversimplification "salting
   prevents cracking."

## Setup

Requires Python 3.9+. No dependencies for the core demo.

```bash
git clone <this-repo>
cd password-security-demo
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt   # only needed to run the tests

# optional: adds a second, industry-standard hashing comparison point
pip install -r requirements-bcrypt.txt
```

## Run it

```bash
python -m pwdemo run
```

```
Scenario             Hash scheme      Method                           Found         Time
-----------------------------------------------------------------------------------------
dictionary_hit       unsalted_md5     Dictionary attack (unsalted)     yes       0.032 ms
dictionary_hit       unsalted_md5     Precomputed lookup table         yes       0.002 ms
dictionary_hit       unsalted_md5     Rainbow chain table              yes       4.436 ms
rainbow_demo         unsalted_md5     Dictionary attack (unsalted)     yes       0.147 ms
rainbow_demo         unsalted_md5     Precomputed lookup table         yes       0.001 ms
rainbow_demo         unsalted_md5     Rainbow chain table              yes       4.223 ms
bruteforce_only      unsalted_md5     Dictionary attack (unsalted)     no        0.299 ms
bruteforce_only      unsalted_md5     Brute-force search (unsalted)    yes     377.430 ms
outside_bounds       unsalted_md5     Dictionary attack (unsalted)     no        0.451 ms
outside_bounds       unsalted_md5     Precomputed lookup table         no        0.001 ms
salted_comparison    salted_pbkdf2    Precomputed lookup table         no        0.002 ms
salted_comparison    salted_pbkdf2    Dictionary attack (salted PBKDF2) yes     641.784 ms

Lookup table:   576 entries, built in 0.41 ms
Rainbow table:  576 stored chains (chain length 60), theoretical coverage 34,560 passwords, built in 83.39 ms

Total demo runtime: 1.13s
```

(This is real, reproduced output — see `examples/sample_run_output.txt`
and `examples/sample_results.json` for the full JSON.)

```bash
python -m pwdemo run --output results.json   # write full JSON results
python -m pwdemo list-scenarios               # see what each scenario is for and why
```

## Reading the results

| Scenario | What it shows |
|---|---|
| `dictionary_hit` | A password that's in the wordlist. Cracked instantly by a live dictionary attack, a plain lookup table, AND a rainbow table — all three work here, but for different reasons (see below). |
| `rainbow_demo` | A second in-wordlist password, used specifically to isolate the rainbow-table result. |
| `bruteforce_only` | Not in the wordlist, but short enough to fall inside the bounded brute-force keyspace — the dictionary attack correctly fails, brute force correctly succeeds. |
| `outside_bounds` | Outside every bound in this demo. Everything fails. **This is not proof the password is secure** — it only proves it's outside this demo's deliberately tiny search space. A real attacker's dictionary and compute budget are enormously larger. |
| `salted_comparison` | The *same* password as `dictionary_hit`, hashed with salted PBKDF2 instead of unsalted MD5. The lookup table fails outright (it was built for unsalted hashes). The dictionary attack still succeeds — but takes roughly **20,000x longer** for the exact same 46-word search, because every single guess now costs a full PBKDF2 computation instead of one MD5 call. |

## Simple lookup table vs. real rainbow table — precisely

Both are **precomputation attacks**: pay the computational cost once,
ahead of time, then reuse it against any number of targets. That's the
idea rainbow tables are named for, and it's genuinely the same idea
behind `lookup_table.py`. But they are not the same technique, and this
project implements both for real rather than describing one and calling
it "basically a rainbow table":

|  | Simple lookup table (`lookup_table.py`) | Rainbow table (`rainbow_chains.py`) |
|---|---|---|
| Stores | Every `(hash, password)` pair — one entry per password | Only each chain's **start and end** password — many passwords per stored entry |
| Lookup cost | One dictionary lookup — effectively instant | Walk up to `chain_length` reduction/hash steps, then regenerate a whole chain to confirm — measurably slower |
| Storage for N passwords | Exactly N entries | Can be far fewer than N entries (see below) |
| This demo's numbers | 576 entries for 576 passwords | 576 stored chains, but a *theoretical coverage* of 34,560 password-slots (576 × chain length 60) |

`tests/test_rainbow_chains.py::test_rainbow_table_uses_less_storage_than_a_lookup_table_for_equal_or_greater_coverage`
demonstrates this directly: for 200 passwords, the lookup table always
stores exactly 200 entries, while a rainbow table over the same
passwords stores at most 200 chains whose theoretical coverage is
2,000+ password-slots — the entire reason rainbow tables exist instead
of "just build a bigger lookup table" at real-world scale (billions of
password hashes).

**Two rainbow-table specifics this implementation gets right, not just
glosses over:**
- **Position-dependent reduction functions.** The function mapping a
  hash back to a password candidate (`reduce_hash`) is different at
  each position in the chain. Skip this and every chain that ever
  collides at any point merges and stays merged forever — this is
  *why* rainbow tables use a different reduction function per column
  (hence "rainbow": one color per column).
- **False alarms.** A candidate chain can land on a stored endpoint by
  coincidence, without the target hash actually being part of that
  chain. `RainbowTable.crack()` regenerates the full candidate chain
  and checks for a real match before accepting it — exactly like a real
  implementation has to.
- **Coverage is probabilistic, not exhaustive.** Chains merge (two
  different starting passwords can reduce to the same endpoint), which
  silently drops some passwords from the table's effective coverage.
  `tests/test_rainbow_chains.py` demonstrates this directly on a tiny,
  fully-enumerated 9-password keyspace, where one specific password
  turns out not to be recoverable from a table built the "obvious"
  way — not a bug, a documented, expected property. The `run_full_comparison()`
  demo works around this the way a real practitioner would: by seeding
  its two demonstrated passwords as the *first* chain starts, which
  guarantees (by construction) that their chains survive any merges.

## Modern salted hashing

`modern_hashing.py` uses **PBKDF2-HMAC-SHA256** (`hashlib.pbkdf2_hmac`)
— a standardized construction from RFC 8018 / NIST SP 800-132, built
into Python's standard library. Two independent properties matter:

- **Salt** (16 random bytes, stored alongside the hash): makes every
  hash unique even for identical passwords, so a precomputed table has
  nothing to match against — it would need a fresh table per salt,
  which erases the entire "compute once, reuse many times" point of
  precomputing at all. `salted_comparison`'s lookup-table row
  demonstrates this failing directly.
- **Iteration count** (50,000, in this demo): each guess must run the
  underlying hash 50,000 times, not once — this project's own benchmark
  puts that at roughly **31,500x slower per guess** than raw MD5. This
  demo's default is deliberately lower than current OWASP guidance
  (600,000+ iterations for PBKDF2-HMAC-SHA256, as of 2023) purely so
  the bounded demo's worst case finishes in single-digit seconds rather
  than half a minute; a production system should use OWASP's current
  recommendation, not this demo's default.

**What this does NOT do:** make a weak, dictionary-guessable password
safe. `salted_comparison` proves this directly — the dictionary attack
against the salted hash still succeeds, just far slower. Salting and
iteration count are real, valuable defenses that belong in every
password system, but they're defense in depth, not a substitute for
requiring genuinely strong, unique passwords.

If the optional `bcrypt` package is installed
(`pip install -r requirements-bcrypt.txt`), `modern_hashing.py` also
exposes `bcrypt_hash()` / `bcrypt_verify()` as a second, widely-used
industry-standard comparison point — nothing else in this project
requires it, and the tests for it skip cleanly if it isn't installed.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

**92 tests pass** (a 93rd, for the optional bcrypt wrapper, runs too if
`bcrypt` is installed — otherwise it skips cleanly rather than failing).
Highlights:

- `test_weak_hashing.py` — deterministic, unsalted behavior, including
  known reference hash values.
- `test_modern_hashing.py` — salting actually varies output, explicit
  salts are reproducible, higher iteration counts really do take
  measurably longer, constant-time comparison is used for verification.
- `test_dictionary_attack.py` / `test_bruteforce_attack.py` — including
  a direct test that `KeyspaceTooLargeError` is raised for any
  charset/length combination exceeding the hard safety cap, regardless
  of parameters requested.
- `test_lookup_table.py` / `test_rainbow_chains.py` — chain generation
  correctness verified on a small, **fully enumerated** keyspace (every
  one of 9 possible passwords, individually confirmed recoverable via
  the real multi-position chain-walk algorithm), plus the storage/coverage
  comparison against a plain lookup table.
- `test_comparison.py` — runs the entire demo end-to-end and asserts on
  its real output (which scenario succeeds via which method, that the
  salted dictionary attack is genuinely >100x slower than the unsalted
  one, that the whole suite finishes in well under 30 seconds).

## Limitations

- **Toy-scale, on purpose.** A ~576-word dictionary and a ~1.7M-entry
  brute-force space are nothing like what a real attacker has access
  to (wordlists with hundreds of millions of entries, GPU/ASIC
  acceleration doing billions of guesses per second). A password that
  resists this demo's bounded attacks is not thereby proven secure —
  `outside_bounds` exists specifically to make that point rather than
  let a "no findings" result be misread as a security guarantee.
- **Fixed password length for the rainbow table.** This is a real
  simplification basic rainbow tables make; production implementations
  handle this with padding/charset tricks this project doesn't attempt.
- **PBKDF2 iteration count is intentionally below current best-practice
  guidance** — see above — purely to keep the bounded demo fast.
- **No GPU/parallelism.** Everything here runs single-threaded, pure
  Python. Real cracking tools (hashcat, John the Ripper) are orders of
  magnitude faster for exactly the kinds of attacks demonstrated here.
- **MD5/SHA-256 as "weak" here means "weak *for password storage*"**
  — both are perfectly good, secure hash functions for other purposes
  (e.g. file integrity checks). The problem demonstrated in this
  project is specifically the lack of salting and iteration count, not
  that MD5 or SHA-256 are "broken" hash functions in general.

## Portfolio description

> **pwdemo** — An educational password-security demonstration comparing
> weak, unsalted hashing against modern salted PBKDF2 hashing, using
> only synthetic passwords and deliberately bounded searches (a
> dictionary attack, a brute-force search with a hard-coded safety cap,
> a precomputed lookup table, and a genuine rainbow table with
> position-dependent reduction functions and real chain-regeneration
> lookup — not a simplified stand-in). Explicitly distinguishes a simple
> lookup table from a true rainbow table with working code and a direct
> storage/coverage comparison, rather than treating them as
> interchangeable. Demonstrates, with real benchmarked numbers, that
> salting defeats precomputation attacks entirely while raising —
> not eliminating — the cost of live dictionary/brute-force attacks.
> 92 automated tests, including exhaustive correctness verification of
> the rainbow-chain algorithm on a fully-enumerated small keyspace.

**Technologies used:** Python 3, `hashlib` (MD5, SHA-256, PBKDF2-HMAC-SHA256),
`hmac` (constant-time comparison), `itertools` (brute-force enumeration),
`dataclasses`; optional `bcrypt` for a second industry-standard hashing
comparison; `pytest` for testing; `argparse` for the CLI;
`pyproject.toml`/`setuptools` for packaging.

**Demo suggestions:**
- A terminal recording of `python -m pwdemo run` start to finish — the
  whole demo completing in ~1 second is itself the "bounded, not a real
  attack tool" point made visually.
- A side-by-side of the `salted_comparison` row's two outcomes: lookup
  table instantly failing vs. the dictionary attack eventually
  succeeding but ~1,600x slower — this is the single most important
  comparison in the whole project.
- A short explainer screen recording walking through `rainbow_chains.py`'s
  docstring alongside the exhaustive 9-password test in
  `test_rainbow_chains.py`, showing a real chain trace end to end.
- `python -m pytest -v` passing, with the rainbow-chain correctness
  tests highlighted specifically — they're the part most demos in this
  space skip in favor of just asserting "rainbow tables are faster."

## License

MIT — see `LICENSE`.
