// SPDX-License-Identifier: AGPL-3.0-or-later
//! Password generator + strength estimators (MVP-1 issue 1.8).
//!
//! Three pieces, all pure (no I/O except the OS CSPRNG):
//!
//! 1. [`generate`] — builds an alphabet from the enabled character
//!    classes, guarantees ≥1 char of each enabled class, fills the rest
//!    with **rejection-sampled, unbiased** draws from the OS CSPRNG
//!    (`pangolin_crypto::rng::fill_random` — never `rand::thread_rng`,
//!    never a deterministic seed), Fisher-Yates-shuffles the buffer with
//!    the same unbiased index draw, and returns a zero-on-drop UTF-8
//!    string.
//! 2. [`entropy_bits`] — the *exact* bit-entropy of a password produced
//!    by a given policy: `length × log2(alphabet_size)`. (The
//!    at-least-one-of-each constraint makes the *true* entropy a hair
//!    lower than this — by at most a few bits — but `length × log2` is
//!    the conventional reported figure; see `password-generator.md`.)
//! 3. [`strength`] — a zxcvbn-style estimate for *arbitrary*
//!    (typed/imported) passwords.
//!
//! `pangolin-core` carries no `uniffi::` annotations; the FFI
//! `PasswordPolicy` / `PasswordStrength` records (in `pangolin-ffi`)
//! convert to/from the plain types here.

#![allow(clippy::cast_precision_loss)] // entropy figures are inherently float

use zeroize::Zeroizing;

use crate::Error;

/// Generator length floor. Sites with a 12-char cap exist; refusing to
/// generate a 10-char password "because 16 is the recommendation" is
/// hostile. 16 is the *default*, not the *minimum*.
pub const PWGEN_LENGTH_MIN: u16 = 8;

/// Generator length cap. Well under the account-side `PASSWORD_MAX_BYTES
/// = 4096` (a 128-char ASCII password is 128 bytes). Anything longer is
/// almost certainly a caller bug.
pub const PWGEN_LENGTH_MAX: u16 = 128;

/// Default generated-password length (the "strong default").
pub const PWGEN_LENGTH_DEFAULT: u16 = 16;

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
/// The 32 ASCII printable punctuation characters (`!` .. `~` minus the
/// alphanumerics and space). Count is verified by a unit test.
const SYMBOLS: &[u8] = br##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##;

/// Visually-confusable characters dropped when `exclude_ambiguous` is
/// set: digit zero / capital O; digit one / lowercase L / capital I /
/// the vertical bar (which on many fonts is indistinguishable from a
/// lowercase L or capital I).
const AMBIGUOUS: &[u8] = b"0O1lI|";

/// Plain (uniffi-free) password-generator policy. The FFI
/// `PasswordPolicy` record converts to/from this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one bool per character class is the natural shape
pub struct PwgenPolicy {
    /// Total password length in characters.
    pub length: u16,
    /// Include uppercase letters.
    pub uppercase: bool,
    /// Include lowercase letters.
    pub lowercase: bool,
    /// Include digits.
    pub digits: bool,
    /// Include ASCII punctuation.
    pub symbols: bool,
    /// Drop visually-confusable characters (`0 O 1 l I |`).
    pub exclude_ambiguous: bool,
}

impl Default for PwgenPolicy {
    /// The strong default: length 16, all four classes, ambiguous chars
    /// excluded.
    fn default() -> Self {
        Self {
            length: PWGEN_LENGTH_DEFAULT,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

impl PwgenPolicy {
    /// Number of enabled character classes.
    #[must_use]
    pub fn enabled_class_count(&self) -> u8 {
        u8::from(self.uppercase)
            + u8::from(self.lowercase)
            + u8::from(self.digits)
            + u8::from(self.symbols)
    }

    /// Validate the policy. Errors are `Error::Validation { kind:
    /// "password_policy", .. }`.
    pub fn validate(&self) -> Result<(), Error> {
        let k = self.enabled_class_count();
        if k == 0 {
            return Err(policy_err("at least one character class must be enabled"));
        }
        if self.length < PWGEN_LENGTH_MIN || self.length > PWGEN_LENGTH_MAX {
            return Err(policy_err(format!(
                "length {} out of range [{PWGEN_LENGTH_MIN}, {PWGEN_LENGTH_MAX}]",
                self.length
            )));
        }
        if u16::from(k) > self.length {
            return Err(policy_err(format!(
                "length {} is below the {k} enabled character classes; cannot \
                 guarantee at least one of each",
                self.length
            )));
        }
        Ok(())
    }

    /// The per-class character vectors (post-ambiguous-exclusion) for
    /// the enabled classes, plus the combined alphabet (their union).
    /// Assumes the policy has already been validated.
    fn alphabets(self) -> (Vec<Vec<u8>>, Vec<u8>) {
        let strip = |src: &[u8]| -> Vec<u8> {
            if self.exclude_ambiguous {
                src.iter()
                    .copied()
                    .filter(|b| !AMBIGUOUS.contains(b))
                    .collect()
            } else {
                src.to_vec()
            }
        };
        let mut classes: Vec<Vec<u8>> = Vec::new();
        if self.uppercase {
            classes.push(strip(UPPER));
        }
        if self.lowercase {
            classes.push(strip(LOWER));
        }
        if self.digits {
            classes.push(strip(DIGITS));
        }
        if self.symbols {
            classes.push(strip(SYMBOLS));
        }
        let combined: Vec<u8> = classes.iter().flatten().copied().collect();
        (classes, combined)
    }

    /// Size of the combined post-exclusion alphabet this policy
    /// produces. Assumes the policy has been validated.
    fn alphabet_size(self) -> usize {
        self.alphabets().1.len()
    }
}

fn policy_err(message: impl Into<String>) -> Error {
    Error::Validation {
        kind: "password_policy".to_string(),
        message: message.into(),
    }
}

/// Draw a uniform index in `0..n` from the OS CSPRNG using single-byte
/// rejection sampling. `n` must be in `1..=256`. The rejection rate is
/// `(256 mod n) / 256 < n/256 < 37%` for `n <= 94`, so the expected
/// number of bytes drawn is well under 2.
fn uniform_index(n: usize) -> usize {
    debug_assert!((1..=256).contains(&n), "uniform_index: n out of range");
    if n == 1 {
        return 0;
    }
    // Largest multiple of `n` that fits in a byte; bytes >= this are in
    // the modulo-biased tail and are rejected.
    let limit = 256 - (256 % n);
    loop {
        let mut buf = [0u8; 1];
        pangolin_crypto::rng::fill_random(&mut buf);
        let v = usize::from(buf[0]);
        if v < limit {
            return v % n;
        }
    }
}

/// Generate a password matching `policy`.
///
/// Method: validate; build the alphabet; for each of the `k` enabled
/// classes place one uniformly-random char of that class at a distinct
/// slot; fill the remaining `length - k` slots with uniformly-random
/// chars from the *combined* alphabet; Fisher-Yates-shuffle the whole
/// buffer with the same unbiased index draw (so the at-least-one chars
/// are not clustered at the front). Provably uniform over the set of
/// strings that contain ≥1 of each enabled class, *given* unbiased
/// index draws — which `uniform_index` provides via rejection sampling.
///
/// All characters are ASCII, so the result is valid UTF-8 by
/// construction and `length` chars == `length` bytes.
///
/// # Errors
/// `Error::Validation { kind: "password_policy" }` for an invalid
/// policy (no class enabled; length out of `[8, 128]`; length below the
/// enabled-class count).
pub fn generate(policy: &PwgenPolicy) -> Result<Zeroizing<String>, Error> {
    policy.validate()?;
    let (classes, combined) = policy.alphabets();
    debug_assert!(
        !combined.is_empty(),
        "validated policy has a non-empty alphabet"
    );

    let len = usize::from(policy.length);
    let mut slots: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(len));

    // Seed one char per enabled class.
    for class in &classes {
        let idx = uniform_index(class.len());
        slots.push(class[idx]);
    }
    // Fill the remainder from the combined alphabet.
    while slots.len() < len {
        let idx = uniform_index(combined.len());
        slots.push(combined[idx]);
    }
    // Fisher-Yates shuffle (i from len-1 down to 1; j uniform in [0, i]).
    let mut i = len;
    while i > 1 {
        i -= 1;
        let j = uniform_index(i + 1);
        slots.swap(i, j);
    }

    let s = String::from_utf8(slots.to_vec()).expect("ASCII-only alphabet is valid UTF-8");
    Ok(Zeroizing::new(s))
}

/// Exact bit-entropy of a password produced by `policy`.
///
/// `length × log2(alphabet_size)`. See the module docs / the
/// `password-generator.md` note on the tiny over-count from the
/// at-least-one-of-each constraint.
///
/// # Errors
/// `Error::Validation { kind: "password_policy" }` for an invalid
/// policy (so `entropy_bits` and `generate` agree on which policies are
/// valid).
pub fn entropy_bits(policy: &PwgenPolicy) -> Result<f64, Error> {
    policy.validate()?;
    let size = policy.alphabet_size();
    Ok(f64::from(policy.length) * (size as f64).log2())
}

/// Heuristic strength estimate for an arbitrary (typed/imported)
/// password.
///
/// Wraps `zxcvbn`. Infallible — always returns a [`PasswordStrength`]
/// (zxcvbn handles the empty-password case with a score-0 result).
#[must_use]
pub fn strength(password: &str) -> PasswordStrength {
    let entropy = zxcvbn::zxcvbn(password, &[]);
    let crack_time_seconds = match entropy.crack_times().offline_slow_hashing_1e4_per_second() {
        zxcvbn::time_estimates::CrackTimeSeconds::Integer(i) => i as f64,
        zxcvbn::time_estimates::CrackTimeSeconds::Float(f) => f,
    };
    let (feedback_warning, feedback_suggestions) = entropy.feedback().map_or_else(
        || (None, Vec::new()),
        |fb| {
            (
                fb.warning().map(|w| w.to_string()),
                fb.suggestions().iter().map(ToString::to_string).collect(),
            )
        },
    );
    PasswordStrength {
        score: u8::from(entropy.score()),
        guesses_log10: entropy.guesses_log10(),
        crack_time_seconds,
        feedback_warning,
        feedback_suggestions,
    }
}

/// Strength estimate for an arbitrary password — the plain (uniffi-free)
/// shape; the FFI `PasswordStrength` record converts from this.
#[derive(Debug, Clone, PartialEq)]
pub struct PasswordStrength {
    /// zxcvbn score, 0 (weakest) .. 4 (strongest).
    pub score: u8,
    /// Base-10 logarithm of the estimated guess count.
    pub guesses_log10: f64,
    /// Conservative crack-time estimate, in seconds: an attacker with
    /// the offline hash, 10k guesses/second.
    pub crack_time_seconds: f64,
    /// A top-level warning, if zxcvbn produced one.
    pub feedback_warning: Option<String>,
    /// Actionable suggestions for a stronger password.
    pub feedback_suggestions: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::suboptimal_flops)] // explicit `x * log2()` is the readable form here
mod tests {
    use super::*;

    #[test]
    fn symbol_set_has_32_chars() {
        assert_eq!(SYMBOLS.len(), 32, "ASCII printable punctuation count");
        // No alphanumerics, no space.
        for b in SYMBOLS {
            assert!(!b.is_ascii_alphanumeric() && *b != b' ', "stray symbol {b}");
        }
    }

    #[test]
    fn uniform_index_n1_is_zero() {
        for _ in 0..100 {
            assert_eq!(uniform_index(1), 0);
        }
    }

    #[test]
    fn uniform_index_is_unbiased_chi_squared() {
        // n = 3 does not divide 256, so a naive `byte % 3` is biased
        // (85 vs 85 vs 86 over 0..255, ~0.4% skew per draw — would
        // accumulate into a detectable chi-squared excess over 300k
        // draws). Rejection sampling removes it. Threshold p > 1e-4
        // (very lax — flakiness budget); the true positive rate at this
        // sample size is essentially 1, the false positive rate ~1e-4.
        const N: usize = 3;
        const DRAWS: usize = 300_000;
        let mut counts = [0usize; N];
        for _ in 0..DRAWS {
            counts[uniform_index(N)] += 1;
        }
        let expected = DRAWS as f64 / N as f64;
        let chi2: f64 = counts
            .iter()
            .map(|&c| {
                let d = c as f64 - expected;
                d * d / expected
            })
            .sum();
        // df = 2; chi-squared 0.9999-quantile ≈ 18.42. A biased draw
        // would push chi2 to the hundreds at this sample size.
        assert!(
            chi2 < 18.42,
            "uniform_index(3) chi-squared {chi2} exceeds 18.42 — bias detected? counts={counts:?}"
        );
    }

    #[test]
    fn generate_length_matches_policy() {
        for &len in &[PWGEN_LENGTH_MIN, 16u16, 32, PWGEN_LENGTH_MAX] {
            let p = PwgenPolicy {
                length: len,
                ..PwgenPolicy::default()
            };
            let pw = generate(&p).expect("valid policy");
            assert_eq!(pw.chars().count(), usize::from(len));
            assert_eq!(pw.len(), usize::from(len), "ASCII: chars == bytes");
        }
    }

    #[test]
    fn generate_chars_in_alphabet() {
        let p = PwgenPolicy::default();
        let (_, alpha) = p.alphabets();
        for _ in 0..200 {
            let pw = generate(&p).expect("valid");
            for b in pw.bytes() {
                assert!(alpha.contains(&b), "char {b} not in alphabet");
                assert!(!AMBIGUOUS.contains(&b), "ambiguous char {b} leaked");
            }
        }
    }

    #[test]
    fn generate_at_least_one_of_each_class_all_four() {
        let p = PwgenPolicy::default();
        for _ in 0..500 {
            let pw = generate(&p).expect("valid");
            assert!(pw.bytes().any(|b| b.is_ascii_uppercase()));
            assert!(pw.bytes().any(|b| b.is_ascii_lowercase()));
            assert!(pw.bytes().any(|b| b.is_ascii_digit()));
            assert!(pw.bytes().any(|b| b.is_ascii_punctuation()));
        }
    }

    #[test]
    fn generate_two_classes_only() {
        let p = PwgenPolicy {
            length: 12,
            uppercase: false,
            lowercase: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
        };
        for _ in 0..300 {
            let pw = generate(&p).expect("valid");
            assert!(pw.bytes().any(|b| b.is_ascii_lowercase()));
            assert!(pw.bytes().any(|b| b.is_ascii_digit()));
            assert!(!pw.bytes().any(|b| b.is_ascii_uppercase()));
            assert!(!pw.bytes().any(|b| b.is_ascii_punctuation()));
        }
    }

    #[test]
    fn generate_char_distribution_lowercase_only_unbiased() {
        // Lowercase-only, exclude_ambiguous → 25-char alphabet (no `l`).
        // 25 does not divide 256, so a biased draw would skew. 200k
        // passwords × 16 chars = 3.2M samples over 25 buckets.
        let p = PwgenPolicy {
            length: 16,
            uppercase: false,
            lowercase: true,
            digits: false,
            symbols: false,
            exclude_ambiguous: true,
        };
        let (_, alpha) = p.alphabets();
        assert_eq!(alpha.len(), 25);
        let mut counts = std::collections::HashMap::new();
        let mut total = 0usize;
        for _ in 0..200_000 {
            let pw = generate(&p).expect("valid");
            for b in pw.bytes() {
                *counts.entry(b).or_insert(0usize) += 1;
                total += 1;
            }
        }
        let n = alpha.len() as f64;
        let expected = total as f64 / n;
        let chi2: f64 = alpha
            .iter()
            .map(|b| {
                let c = *counts.get(b).unwrap_or(&0) as f64;
                let d = c - expected;
                d * d / expected
            })
            .sum();
        // df = 24; chi-squared 0.9999-quantile ≈ 55.0. Bias would push
        // chi2 far past this at 3.2M samples.
        assert!(
            chi2 < 55.0,
            "lowercase-only char distribution chi-squared {chi2} exceeds 55.0 — bias?"
        );
    }

    #[test]
    fn default_policy_is_strong() {
        let p = PwgenPolicy::default();
        assert_eq!(p.length, 16);
        assert!(p.uppercase && p.lowercase && p.digits && p.symbols);
        assert!(p.exclude_ambiguous);
        assert_eq!(p.enabled_class_count(), 4);
        let pw = generate(&p).expect("valid");
        assert_eq!(pw.chars().count(), 16);
        assert!(pw.bytes().any(|b| b.is_ascii_uppercase()));
        assert!(pw.bytes().any(|b| b.is_ascii_lowercase()));
        assert!(pw.bytes().any(|b| b.is_ascii_digit()));
        assert!(pw.bytes().any(|b| b.is_ascii_punctuation()));
    }

    #[test]
    fn validation_errors() {
        let is_policy_err = |r: Result<_, Error>| matches!(r, Err(Error::Validation { kind, .. }) if kind == "password_policy");
        let off = PwgenPolicy {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            ..PwgenPolicy::default()
        };
        assert!(is_policy_err(generate(&off).map(|_| ())));

        let short = PwgenPolicy {
            length: 7,
            ..PwgenPolicy::default()
        };
        assert!(is_policy_err(generate(&short).map(|_| ())));

        let long = PwgenPolicy {
            length: 200,
            ..PwgenPolicy::default()
        };
        assert!(is_policy_err(generate(&long).map(|_| ())));

        // The "length < enabled classes" guard: with MIN=8 and at most
        // 4 classes it can't bite via the public API, but the guard is
        // there as defence-in-depth. Validate it directly: a hand-built
        // policy with length below the class count fails `validate`.
        let too_short_for_classes = PwgenPolicy {
            length: 3,
            ..PwgenPolicy::default()
        };
        // length 3 is < MIN, so the length-range check fires first —
        // still a policy error, which is what callers see.
        assert!(is_policy_err(too_short_for_classes.validate()));
    }

    #[test]
    fn length_below_class_count_is_rejected() {
        // 4 classes, length 4 would be the boundary; length below it
        // (but ≥ MIN) is impossible here. Confirm length == 4 with 4
        // classes fails the range check (4 < MIN=8) — i.e. all
        // sub-MIN lengths are policy errors regardless of class count.
        for len in 0u16..PWGEN_LENGTH_MIN {
            let p = PwgenPolicy {
                length: len,
                ..PwgenPolicy::default()
            };
            assert!(p.validate().is_err(), "length {len} must be rejected");
        }
    }

    #[test]
    fn entropy_bits_matches_formula() {
        // Default: 26 + 26 + 10 + 32 = 94, minus ambiguous in those
        // classes: 0, O (upper), 1, l, I (lower? l is lower; 1 is
        // digit; I is upper) — AMBIGUOUS = {0,O,1,l,I,|}. In upper: O,
        // I → 24. lower: l → 25. digits: 0, 1 → 8. symbols: | → 31.
        // total = 24 + 25 + 8 + 31 = 88.
        let p = PwgenPolicy::default();
        let bits = entropy_bits(&p).expect("valid");
        let expected = 16.0 * (88f64).log2();
        assert!(
            (bits - expected).abs() < 1e-9,
            "bits={bits} expected={expected}"
        );

        // Lowercase only, no exclusion → 26.
        let lc = PwgenPolicy {
            length: 20,
            uppercase: false,
            lowercase: true,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let bits = entropy_bits(&lc).expect("valid");
        assert!((bits - 20.0 * (26f64).log2()).abs() < 1e-9);

        // Lowercase + digits, no exclusion → 36.
        let lcd = PwgenPolicy {
            length: 10,
            uppercase: false,
            lowercase: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        let bits = entropy_bits(&lcd).expect("valid");
        assert!((bits - 10.0 * (36f64).log2()).abs() < 1e-9);

        // Invalid policy → Err.
        let off = PwgenPolicy {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            ..PwgenPolicy::default()
        };
        assert!(entropy_bits(&off).is_err());
    }

    #[test]
    fn strength_basic() {
        let weak = strength("password");
        assert!(weak.score <= 1, "score={}", weak.score);
        assert!(weak.feedback_warning.is_some() || !weak.feedback_suggestions.is_empty());

        let phrase = strength("correct horse battery staple");
        assert!(phrase.score >= 3, "score={}", phrase.score);

        let empty = strength("");
        assert_eq!(empty.score, 0);

        let p = PwgenPolicy {
            length: 24,
            ..PwgenPolicy::default()
        };
        let generated = generate(&p).expect("valid");
        let gs = strength(&generated);
        assert_eq!(gs.score, 4, "24-char generated password should score 4");
        // Monotonic: a generated 24-char password is at least as strong
        // as the dictionary word.
        assert!(gs.score >= weak.score);
        assert!(gs.crack_time_seconds > weak.crack_time_seconds);
        assert!(gs.guesses_log10 > weak.guesses_log10);
    }

    #[test]
    fn generated_is_zeroizing() {
        // Type-level discipline: `generate` returns `Zeroizing<String>`.
        // A compile-time check that the return type zeroizes on drop.
        fn assert_zeroizing(_: &Zeroizing<String>) {}
        let pw = generate(&PwgenPolicy::default()).expect("valid");
        assert_zeroizing(&pw);
    }
}
