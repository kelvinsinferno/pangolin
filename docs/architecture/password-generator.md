<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Password generator (MVP-1 issue 1.8)

> **Status:** Locked 2026-05-12 by MVP-1 issue 1.8
> (`docs/issue-plans/1.8.md`). Implemented in `pangolin_core::pwgen`;
> exposed over FFI as `password_generate` / `password_entropy_bits` /
> `password_strength` / `password_policy_default` (see
> `docs/architecture/ffi-surface.md`).

## Why it's security-relevant

The generator produces a *secret*. Two properties carry the weight:

1. **CSPRNG.** All entropy comes from the OS CSPRNG, reached through
   `pangolin_crypto::rng::fill_random` (the audited chokepoint;
   `getrandom`/`BCryptGenRandom`/`getentropy`). Never `rand::thread_rng`,
   never a deterministic seed. The deterministic-RNG `_with` surface in
   `pangolin-crypto` is crate-private (MEDIUM-11) so it cannot be
   reached from `pangolin-core` even by accident.
2. **Unbiased character selection.** Each character is drawn uniformly
   from the alphabet. The naive `byte % alphabet_len` is biased when
   `alphabet_len` doesn't divide 256 — and the alphabets here (25 / 31 /
   88 / 94 chars …) never do — which shrinks the effective keyspace.
   The generator uses **rejection sampling**: draw a byte, accept it
   only if `byte < 256 - (256 mod n)` (i.e. it's in the largest
   `n`-divisible prefix), then return `byte mod n`. The rejection rate
   is `(256 mod n) / 256 < n/256 < 37%` for `n ≤ 94`, so the expected
   number of bytes per index is well under 2. Helper:
   `pwgen::uniform_index(n)` for `n ∈ 1..=256`.

A statistical test (`pwgen::tests::generate_char_distribution_lowercase_only_unbiased`,
≈3.2M samples over a 25-char alphabet, χ² with a very lax `p > 1e-4`
threshold) and a direct rejection-sampling test
(`uniform_index_is_unbiased_chi_squared`, 300k draws over `n = 3`)
guard property 2. They are regular `#[test]`s — no timing assertions.

## Alphabet

Four character classes, toggled independently in `PasswordPolicy`:

| Class | Characters | Count |
|---|---|---:|
| uppercase | `A`–`Z` | 26 |
| lowercase | `a`–`z` | 26 |
| digits | `0`–`9` | 10 |
| symbols | the 32 ASCII printable punctuation chars: `` !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ `` | 32 |

**Full ASCII symbol set** (Kelvin's call — maximum entropy from the
symbol class). Trade-off accepted: some password fields reject certain
ASCII symbols (`< > " ' \` …); a "curated safe-symbols" variant could be
added later as another `PasswordPolicy` option, but the default-on set
is the full one.

### `exclude_ambiguous` (default `true`)

When set, the visually-confusable characters `0 O 1 l I |` are removed
from whichever classes are enabled:

- `0` (digit zero) / `O` (capital O)
- `1` (digit one) / `l` (lowercase L) / `I` (capital I)
- `|` (vertical bar — on many fonts indistinguishable from `l`/`I`)

So the post-exclusion class sizes are: uppercase 24, lowercase 25,
digits 8, symbols 31. The default policy (all four classes,
`exclude_ambiguous: true`) has a **88-char** alphabet.

## Strong defaults

`PasswordPolicy::default()` / `password_policy_default()`:

| Field | Value |
|---|---|
| `length` | 16 |
| `uppercase` / `lowercase` / `digits` / `symbols` | all `true` |
| `exclude_ambiguous` | `true` |

Matches the master-plan row's "16+ chars, mixed case + digits +
symbols". A 16-char password over an 88-char alphabet ≈ **103 bits** of
entropy — far past "deeply uncrackable".

## Length floor / cap

`PWGEN_LENGTH_MIN = 8`, `PWGEN_LENGTH_MAX = 128`,
`PWGEN_LENGTH_DEFAULT = 16`. A low floor is deliberate: sites with a
12-char (or shorter) cap exist, and refusing to generate a 10-char
password "because 16 is the recommendation" is hostile. 16 is the
*default*, not the *minimum*. Additionally `length` must be ≥ the count
of enabled character classes so the at-least-one-of-each guarantee is
satisfiable. An invalid policy (no class enabled; `length` outside
`[8, 128]`; `length` below the enabled-class count) → a typed
`Validation { kind: "password_policy" }` error — the generator fails
loudly rather than clamping (a generated password that silently matched
a *different* policy than the caller asked for is a bad failure mode).

This is **distinct from the account-side `PASSWORD_MAX_BYTES = 4096`**
(see `account-limits.md`): `PWGEN_*` bounds what the generator
*produces*; `PASSWORD_MAX_BYTES` bounds what the vault *accepts* for any
user-supplied `current_password`. A 128-char generated password is 128
bytes — well under 4096.

## Construction: place-then-shuffle

To guarantee ≥1 character of each enabled class without skewing the
distribution:

1. For each of the `k` enabled classes, draw one uniformly-random char
   of that class (rejection-sampled) and place it at the next slot.
2. Fill the remaining `length − k` slots with uniformly-random chars
   from the *combined* alphabet (rejection-sampled).
3. **Fisher-Yates shuffle** the whole `length`-byte buffer: for `i`
   from `length−1` down to `1`, draw `j` uniform in `[0, i]`
   (rejection-sampled) and swap `slots[i]` with `slots[j]`. So the
   seeded chars are not clustered at the front.

This is provably uniform over *the set of strings that contain ≥1 of
each enabled class*, **given** unbiased index draws — which the
rejection-sampling helper provides. It's `O(length)` and never loops
unboundedly.

The result is all-ASCII, so it's valid UTF-8 by construction and
`length` chars == `length` bytes. The generated buffer is wrapped in
`Zeroizing<String>` (zeroes on drop); the FFI `password_generate` moves
the bytes into `SecretPassword` (the existing zeroizing `Arc<>` wrapper)
and the now-empty `Zeroizing<String>` zeroes its freed allocation.

## Entropy

`password_entropy_bits(policy) = length × log2(alphabet_size)` where
`alphabet_size` is the size of the combined post-exclusion alphabet that
`policy` produces (computed by the same code path `generate` uses, so
the two stay in sync). For a *generated* password with a known policy
this is *exact*, not an estimate.

**Conventional over-count.** The at-least-one-of-each constraint
excludes a tiny fraction of strings, so the *true* entropy is a hair
below `length × log2(alphabet)` — by at most a few bits, and a fraction
of a bit when `length ≫ k`. `length × log2(alphabet)` is the standard
reported figure (it's what every "entropy: N bits" indicator shows);
the over-count is noted here for completeness.

An invalid policy → `Validation { kind: "password_policy" }` (so
`password_entropy_bits` and `password_generate` agree on which policies
are valid).

## Strength estimator (zxcvbn) — for arbitrary passwords

`password_strength(password: &str)` runs the `zxcvbn` crate
(v3.1.1, MIT/Apache, `no_unsafe = true`, in `pangolin-core`'s tree —
`default-features = false` drops the bundled `builder` feature) on an
*arbitrary* (typed/imported) password and returns a `PasswordStrength`:

| Field | Source |
|---|---|
| `score: u8` (0–4) | `Entropy::score()` → `u8::from(Score)` |
| `guesses_log10: f64` | `Entropy::guesses_log10()` |
| `crack_time_seconds: f64` | `Entropy::crack_times().offline_slow_hashing_1e4_per_second()` — the conservative "attacker has your offline hash, 10k guesses/sec" figure (the one a security-conscious UI shows) |
| `feedback_warning: Option<String>` | `Entropy::feedback().and_then(|f| f.warning())` |
| `feedback_suggestions: Vec<String>` | `Entropy::feedback().map(|f| f.suggestions())` |

`zxcvbn::zxcvbn` in 3.x is **infallible** — `strength` always returns a
`PasswordStrength` (the empty-password case yields score 0 with a
warning; no panic). zxcvbn is a *heuristic estimator* (dictionary /
keyboard-walk / l33t-substitution / repeat patterns), not a parser of
attacker-structured data, so it doesn't get the separate-crate
blast-containment treatment that `pangolin-totp` / `pangolin-kdbx` give
their parser deps; `pangolin-core` is its natural home.

**Deferred:** passing the account's display-name / usernames as
zxcvbn's `user_inputs` so a password that *contains* them is penalised —
a nice future enhancement (needs the per-account context plumbed
through); for now `user_inputs = &[]`.

## Per-site overrides

"Per-site override" in MVP-1 means *the caller passes whatever
`PasswordPolicy` that site needs* on the `password_generate` call. There
is **no** policy persisted on the `AccountIdentity` — storing one would
be another `payload_version` bump on the CBOR body, an MVP-3+ concern.

## CLI

`pangolin-cli account add --generate-password` (issue 1.8) routes
through this generator with `PasswordPolicy::default()` — a 16-char
strong-default password. (The divergent local 64-char generator that
predated the FFI entry has been removed.) The generated value is printed
to **stderr** inside a clearly-flagged save-this-now block (stdout is
reserved for the `account_id`); copy it into the user's preferred
password store. Accepted limitation (same posture as the `reveal_*`
notes): a generated password printed to a terminal lands in scrollback /
shell history.

## Out of scope (deferred)

- **Deterministic / re-derivable password generation** ("Deterministic
  regeneration option (advanced)" — a master-secret-+-site-name stateless
  derivation, à la LessPass) — MVP-3+, and arguably a misfeature for a
  vault-based manager (it trades per-credential isolation for a single
  master-input dependency). The 1.8 generator is purely CSPRNG-based.
- **zxcvbn `user_inputs`-aware strength** (penalise passwords containing
  the account's own display-name / usernames) — MVP-3+.
- **A curated "safe-symbols" `PasswordPolicy` variant** — MVP-3+ if a
  real site-compat need shows up.
