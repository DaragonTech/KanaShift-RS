// phonoshift/src/lib.rs
// ROT500K Family / PhonoShift — Base Library (Rust port)

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// Verified result for ROT500KV / ROT500KT / ROT500KP decrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedResult {
    pub ok: bool,
    pub value: String,
}

// -----------------------------
// Core helpers (match Python/JS)
// -----------------------------

fn is_separator(ch: char) -> bool {
    matches!(ch, ' ' | '-' | '\'')
}

fn is_digit(ch: char) -> bool {
    ch >= '0' && ch <= '9'
}

fn is_ascii_upper(ch: char) -> bool {
    ch >= 'A' && ch <= 'Z'
}

fn is_ascii_lower(ch: char) -> bool {
    ch >= 'a' && ch <= 'z'
}

fn to_lower_ascii(ch: char) -> char {
    if is_ascii_upper(ch) {
        ((ch as u8) | 0x20) as char
    } else {
        ch
    }
}

fn to_upper_ascii(ch: char) -> char {
    if is_ascii_lower(ch) {
        ((ch as u8) & !0x20) as char
    } else {
        ch
    }
}

fn effective_shift(shift: i32, set_size: i32) -> i32 {
    if set_size <= 1 {
        return 0;
    }
    let mut m = shift.rem_euclid(set_size);
    if m == 0 {
        m = if shift >= 0 { 1 } else { -1 };
    }
    m
}

fn rotate_in_set_no_zero(set_chars: &str, ch: char, shift: i32) -> char {
    let n = set_chars.chars().count() as i32;
    let idx = set_chars.chars().position(|x| x == ch);
    let Some(idx) = idx else { return ch };
    let idx = idx as i32;

    let eff = effective_shift(shift, n);
    let j = (idx + eff).rem_euclid(n) as usize;

    set_chars.chars().nth(j).unwrap_or(ch)
}

fn derive_keystream(password: &str, salt: &str, iterations: u32, need_bytes: usize) -> Vec<u8> {
    let mut need = need_bytes.max(32);
    // pbkdf2 takes output buffer length; allocate exactly what we need
    let mut out = vec![0u8; need];
    let iters = iterations.max(1);

    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iters, &mut out);
    // keep exactly need bytes (already)
    need = out.len();
    out
}

fn transform_name_like_fpe(s: &str, password: &str, iterations: u32, salt: &str, direction: i32) -> String {
    const VOW_LO: &str = "aeiou";
    const CON_LO: &str = "bcdfghjklmnpqrstvwxyz";

    const VOW_LO_PT: &str = "áàâãäéèêëíìîïóòôõöúùûü";
    const VOW_UP_PT: &str = "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜ";

    const CON_LO_PT: &str = "ç";
    const CON_UP_PT: &str = "Ç";

    if s.is_empty() {
        return s.to_string();
    }

    let ks = derive_keystream(password, salt, iterations, s.chars().count() + 64);
    let mut kpos: usize = 0;

    let mut out = String::with_capacity(s.len());

    for c in s.chars() {
        if is_separator(c) {
            out.push(c);
            continue;
        }

        let shift = ((ks[kpos] as i32) + 1) * direction;
        kpos += 1;
        if kpos >= ks.len() {
            kpos = 0;
        }

        // Digits: strict, invertible
        if is_digit(c) {
            let d = (c as u8 - b'0') as i32;
            let nd = (d + (shift % 10) + 10) % 10;
            out.push((b'0' + (nd as u8)) as char);
            continue;
        }

        let upper = is_ascii_upper(c) || VOW_UP_PT.contains(c) || CON_UP_PT.contains(c);

        let mut lc = c;
        if is_ascii_upper(lc) {
            lc = to_lower_ascii(lc);
        }

        if VOW_LO.contains(lc) {
            let mut ch = rotate_in_set_no_zero(VOW_LO, lc, shift);
            if upper {
                ch = to_upper_ascii(ch);
            }
            out.push(ch);
            continue;
        }

        if CON_LO.contains(lc) {
            let mut ch = rotate_in_set_no_zero(CON_LO, lc, shift);
            if upper {
                ch = to_upper_ascii(ch);
            }
            out.push(ch);
            continue;
        }

        if VOW_LO_PT.contains(c) {
            out.push(rotate_in_set_no_zero(VOW_LO_PT, c, shift));
            continue;
        }
        if VOW_UP_PT.contains(c) {
            out.push(rotate_in_set_no_zero(VOW_UP_PT, c, shift));
            continue;
        }

        if CON_LO_PT.contains(c) {
            out.push(rotate_in_set_no_zero(CON_LO_PT, c, shift));
            continue;
        }
        if CON_UP_PT.contains(c) {
            out.push(rotate_in_set_no_zero(CON_UP_PT, c, shift));
            continue;
        }

        out.push(c);
    }

    out
}

// -----------------------------
// Optional punctuation shifting (only ¿¡ and !?)
// -----------------------------

const P_OPEN: &str = "¿¡";
const P_END: &str = "!?";

fn is_shift_punct(ch: char) -> bool {
    P_OPEN.contains(ch) || P_END.contains(ch)
}

fn punct_shift_apply(s: &str, password: &str, iterations: u32, salt: &str, direction: i32) -> String {
    if s.is_empty() {
        return s.to_string();
    }

    let need = s.chars().filter(|&c| is_shift_punct(c)).count();
    if need == 0 {
        return s.to_string();
    }

    let punct_salt = format!("{salt}|PunctShift:v1");
    let ks = derive_keystream(password, &punct_salt, iterations, need + 64);

    let mut out: Vec<char> = s.chars().collect();
    let mut kpos: usize = 0;

    for c in out.iter_mut() {
        if !is_shift_punct(*c) {
            continue;
        }

        let shift = ((ks[kpos] as i32) + 1) * direction;
        kpos += 1;
        if kpos >= ks.len() {
            kpos = 0;
        }

        if P_OPEN.contains(*c) {
            *c = rotate_in_set_no_zero(P_OPEN, *c, shift);
        } else {
            *c = rotate_in_set_no_zero(P_END, *c, shift);
        }
    }

    out.into_iter().collect()
}

// -----------------------------
// Public APIs: ROT500K (base)
// -----------------------------

pub fn rot500k_encrypt(
    name: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let mut r = transform_name_like_fpe(name, password, iterations, salt, 1);
    if shift_punctuation {
        r = punct_shift_apply(&r, password, iterations, salt, 1);
    }
    r
}

pub fn rot500k_decrypt(
    obfuscated: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let mut s = obfuscated.to_string();
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, -1);
    }
    transform_name_like_fpe(&s, password, iterations, salt, -1)
}

// -----------------------------
// HMAC helpers
// -----------------------------

fn hmac_sha256_bytes(key_str: &str, msg_str: &str) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key_str.as_bytes()).expect("HMAC key");
    mac.update(msg_str.as_bytes());
    let res = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res[..32]);
    out
}

// -----------------------------
// ROT500KT (token-verified)
// -----------------------------

fn is_token_sep(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '-' | '\'' | '.' | ',' | '!' | '?' | ':' | ';' | '\t' | '\n' | '\r'
    )
}

fn is_all_digits_str(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_digit)
}

fn is_all_upper_ascii(s: &str) -> bool {
    let mut has_letter = false;
    for c in s.chars() {
        if (c >= 'a') && (c <= 'z') {
            return false;
        }
        if (c >= 'A') && (c <= 'Z') {
            has_letter = true;
        }
    }
    has_letter
}

const CONSET: &str = "bcdfghjklmnpqrstvwxyz";

fn token_digest(password: &str, salt: &str, iterations: u32, token_index: usize, token_plain: &str) -> [u8; 32] {
    let msg = format!("PhonoShiftTok:v1|{salt}|{iterations}|{token_index}|{token_plain}");
    hmac_sha256_bytes(password, &msg)
}

fn make_token_check(token_plain: &str, kind: &str, mac: &[u8; 32], check_chars_per_token: usize) -> String {
    let n = check_chars_per_token.max(1);
    let upper_mode = (kind == "alpha") && is_all_upper_ascii(token_plain);

    let consonants: Vec<char> = CONSET.chars().collect();

    let mut out = String::with_capacity(n);
    for i in 0..n {
        let b = mac[(i * 7) & 31];
        if kind == "digits" {
            out.push((b'0' + (b % 10)) as char);
        } else {
            let mut ch = consonants[(b as usize) % consonants.len()];
            if upper_mode {
                // only ASCII in CONSET; safe
                ch = to_upper_ascii(ch);
            }
            out.push(ch);
        }
    }
    out
}

fn build_plain_token_checks(
    plain: &str,
    password: &str,
    salt: &str,
    iterations: u32,
    check_chars_per_token: usize,
) -> Vec<String> {
    let mut checks: Vec<String> = Vec::new();
    let mut tok = String::new();
    let mut tok_idx: usize = 0;

    let mut flush = |tok: &mut String, tok_idx: &mut usize, checks: &mut Vec<String>| {
        if tok.is_empty() {
            return;
        }
        let kind = if is_all_digits_str(tok) { "digits" } else { "alpha" };
        let mac = token_digest(password, salt, iterations, *tok_idx, tok);
        checks.push(make_token_check(tok, kind, &mac, check_chars_per_token));
        *tok_idx += 1;
        tok.clear();
    };

    for c in plain.chars() {
        if is_token_sep(c) {
            flush(&mut tok, &mut tok_idx, &mut checks);
        } else {
            tok.push(c);
        }
    }
    flush(&mut tok, &mut tok_idx, &mut checks);

    checks
}

fn attach_checks_to_cipher(cipher: &str, checks: &[String]) -> Result<String, String> {
    let mut out = String::with_capacity(cipher.len() + checks.len());
    let mut tok = String::new();
    let mut tok_idx: usize = 0;

    let mut flush = |tok: &mut String, out: &mut String, tok_idx: &mut usize| -> Result<(), String> {
        if tok.is_empty() {
            return Ok(());
        }
        if *tok_idx >= checks.len() {
            return Err("ROT500K_TokenTagged: token/check count mismatch.".to_string());
        }
        out.push_str(tok);
        out.push_str(&checks[*tok_idx]);
        *tok_idx += 1;
        tok.clear();
        Ok(())
    };

    for c in cipher.chars() {
        if is_token_sep(c) {
            flush(&mut tok, &mut out, &mut tok_idx)?;
            out.push(c);
        } else {
            tok.push(c);
        }
    }
    flush(&mut tok, &mut out, &mut tok_idx)?;

    if tok_idx != checks.len() {
        return Err("ROT500K_TokenTagged: unused checks remain.".to_string());
    }

    Ok(out)
}

fn strip_checks_from_tagged(tagged: &str, check_chars_per_token: usize) -> Option<(String, Vec<String>)> {
    let n = check_chars_per_token.max(1);

    let mut base = String::with_capacity(tagged.len());
    let mut given: Vec<String> = Vec::new();
    let mut tok = String::new();

    let mut flush = |tok: &mut String, base: &mut String, given: &mut Vec<String>| -> bool {
        if tok.is_empty() {
            return true;
        }
        if tok.chars().count() <= n {
            return false;
        }
        // split by chars (ASCII in this family; safe)
        let chars: Vec<char> = tok.chars().collect();
        let chk: String = chars[chars.len() - n..].iter().collect();
        let base_tok: String = chars[..chars.len() - n].iter().collect();

        given.push(chk);
        base.push_str(&base_tok);
        tok.clear();
        true
    };

    for c in tagged.chars() {
        if is_token_sep(c) {
            if !flush(&mut tok, &mut base, &mut given) {
                return None;
            }
            base.push(c);
        } else {
            tok.push(c);
        }
    }

    if !flush(&mut tok, &mut base, &mut given) {
        return None;
    }

    Some((base, given))
}

pub fn rot500k_token_tagged(
    name: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    let cipher = transform_name_like_fpe(name, password, iterations, salt, 1);
    let checks = build_plain_token_checks(name, password, salt, iterations, check_chars_per_token);
    let mut out = attach_checks_to_cipher(&cipher, &checks)?;

    if shift_punctuation {
        out = punct_shift_apply(&out, password, iterations, salt, 1);
    }
    Ok(out)
}

pub fn rot500k_token_tagged_decrypt(
    tagged: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> VerifiedResult {
    let mut s = tagged.to_string();
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, -1);
    }

    let Some((base_cipher, given_checks)) = strip_checks_from_tagged(&s, check_chars_per_token) else {
        return VerifiedResult { ok: false, value: String::new() };
    };

    let plain = transform_name_like_fpe(&base_cipher, password, iterations, salt, -1);
    let expected = build_plain_token_checks(&plain, password, salt, iterations, check_chars_per_token);

    if expected.len() != given_checks.len() {
        return VerifiedResult { ok: false, value: String::new() };
    }

    for (a, b) in expected.iter().zip(given_checks.iter()) {
        if a != b {
            return VerifiedResult { ok: false, value: String::new() };
        }
    }

    VerifiedResult { ok: true, value: plain }
}

// -----------------------------
// ROT500KP (prefix-verified)
// -----------------------------

const ROT500K_TAG_DOMAIN: &str = "PhonoShiftTag:v1";
const PT_LETTERS: &str = "áàâãäéèêëíìîïóòôõöúùûüÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜçÇ";

fn only_letters_ascii_or_pt(c: char) -> bool {
    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || PT_LETTERS.contains(c)
}

fn detect_case_style(plain: &str) -> &'static str {
    let mut has_letter = false;
    let mut any_upper = false;
    let mut any_lower = false;

    for c in plain.chars() {
        if !only_letters_ascii_or_pt(c) {
            continue;
        }
        has_letter = true;

        if c >= 'A' && c <= 'Z' {
            any_upper = true;
        } else if c >= 'a' && c <= 'z' {
            any_lower = true;
        } else {
            // PT letters: treat as mixed
            any_upper = true;
            any_lower = true;
        }
    }

    if !has_letter {
        return "title";
    }
    if any_upper && !any_lower {
        return "upper";
    }
    if any_lower && !any_upper {
        return "lower";
    }
    "title"
}

fn apply_case_style_to_word(w: &str, style: &str) -> String {
    if w.is_empty() {
        return String::new();
    }
    match style {
        "upper" => w.to_uppercase(),
        "lower" => w.to_lowercase(),
        _ => {
            // title: upper first, lower rest (ASCII-ish; matches Python intent)
            let low = w.to_lowercase();
            let mut chars = low.chars();
            let Some(first) = chars.next() else { return String::new() };
            let mut out = String::new();
            out.push_str(&first.to_uppercase().to_string());
            out.push_str(&chars.collect::<String>());
            out
        }
    }
}

fn apply_case_style_to_phrase(phrase: &str, style: &str) -> String {
    phrase
        .split(' ')
        .map(|p| apply_case_style_to_word(p, style))
        .collect::<Vec<_>>()
        .join(" ")
}

fn make_pronounceable_word_from_bytes(mac: &[u8; 32], offset: usize, syllables: usize) -> String {
    const CSET: &str = "bcdfghjklmnpqrstvwxyz";
    const VSET: &str = "aeiou";
    let cchars: Vec<char> = CSET.chars().collect();
    let vchars: Vec<char> = VSET.chars().collect();

    let mut out = String::with_capacity(syllables * 2);
    for i in 0..syllables {
        let x = mac[(offset + i) & 31];
        let c_idx = (x as usize) % cchars.len();
        let v_idx = ((x as usize) / cchars.len()) % vchars.len();
        out.push(cchars[c_idx]);
        out.push(vchars[v_idx]);
    }
    out
}

fn pick_punct_from_bytes(mac: &[u8; 32]) -> &'static str {
    // Python: "? " or "! "
    if (mac[0] % 2) == 0 { "? " } else { "! " }
}

fn build_tag_prefix_for_plaintext(plain: &str, password: &str, iterations: u32, salt: &str) -> String {
    let msg = format!("{ROT500K_TAG_DOMAIN}|{salt}|{iterations}|{plain}");
    let mac = hmac_sha256_bytes(password, &msg);

    let w1 = make_pronounceable_word_from_bytes(&mac, 1, 3);
    let w2 = make_pronounceable_word_from_bytes(&mac, 4, 3);
    let mut phrase = format!("{w1} {w2}");

    let punct = pick_punct_from_bytes(&mac);
    let style = detect_case_style(plain);
    phrase = apply_case_style_to_phrase(&phrase, style);

    // ends with space
    format!("{phrase}{punct}")
}

fn split_tagged_prefix(tagged: &str) -> Option<(String, String)> {
    let chars: Vec<char> = tagged.chars().collect();
    if chars.len() < 3 {
        // Need at least: "<punct><space><something>"
        return None;
    }

    // We access i+1, so i must be <= len-2.
    for i in 0..(chars.len() - 1) {
        if (chars[i] == '?' || chars[i] == '!') && chars[i + 1] == ' ' {
            // Need i+2 to exist (cipher must start at i+2)
            if i + 2 >= chars.len() {
                return None;
            }

            let prefix: String = chars[..=i].iter().collect();      // includes punct, no space
            let cipher: String = chars[i + 2..].iter().collect();   // after "<punct><space>"
            if cipher.is_empty() {
                return None;
            }
            return Some((prefix, cipher));
        }
    }

    None
}

pub fn rot500k_prefix_tagged(
    name: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let cipher = transform_name_like_fpe(name, password, iterations, salt, 1);
    let prefix = build_tag_prefix_for_plaintext(name, password, iterations, salt);
    let mut out = format!("{prefix}{cipher}");
    if shift_punctuation {
        out = punct_shift_apply(&out, password, iterations, salt, 1);
    }
    out
}

pub fn rot500k_prefix_tagged_decrypt(
    tagged: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> VerifiedResult {
    let mut s = tagged.to_string();
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, -1);
    }

    let Some((prefix_given, cipher)) = split_tagged_prefix(&s) else {
        return VerifiedResult { ok: false, value: String::new() };
    };

    let plain = transform_name_like_fpe(&cipher, password, iterations, salt, -1);
    let expected = build_tag_prefix_for_plaintext(&plain, password, iterations, salt);
    let expected_no_space = expected[..expected.len().saturating_sub(1)].to_string();

    if expected_no_space != prefix_given {
        return VerifiedResult { ok: false, value: String::new() };
    }

    VerifiedResult { ok: true, value: plain }
}

// -----------------------------
// ROT500KV (verified auto-select)
// -----------------------------

fn contains_structured_delimiters(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '{' | '}' | '[' | ']' | '"' | '\\' | '<' | '>' | '=' | ':' ))
}

fn count_tokens_simple(s: &str) -> usize {
    let mut count = 0usize;
    let mut in_tok = false;

    for c in s.chars() {
        if is_token_sep(c) {
            in_tok = false;
        } else if !in_tok {
            count += 1;
            in_tok = true;
        }
    }
    count
}

fn min_token_len_simple(s: &str) -> usize {
    let mut min_len: Option<usize> = None;
    let mut cur = 0usize;
    let mut in_tok = false;

    for c in s.chars() {
        if is_token_sep(c) {
            if in_tok {
                min_len = Some(min_len.map_or(cur, |m| m.min(cur)));
            }
            cur = 0;
            in_tok = false;
        } else {
            in_tok = true;
            cur += 1;
        }
    }
    if in_tok {
        min_len = Some(min_len.map_or(cur, |m| m.min(cur)));
    }

    min_len.unwrap_or(0)
}

fn should_use_token_tagged(plain: &str, check_chars_per_token: usize) -> bool {
    let n = check_chars_per_token.max(1);
    if contains_structured_delimiters(plain) {
        return false;
    }
    let tok_count = count_tokens_simple(plain);
    let min_len = min_token_len_simple(plain);
    tok_count >= 2 && min_len > n && plain.chars().count() >= 6
}

fn looks_like_rot500k_cipher(s: &str, check_chars_per_token: usize) -> bool {
    let n = check_chars_per_token.max(1);
    if s.is_empty() {
        return false;
    }

    let trimmed = s.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if trimmed.is_empty() {
        return false;
    }

    fn is_ascii_letter(ch: char) -> bool {
        (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
    }

    fn is_consonant_ascii(ch: char) -> bool {
        let low = if ch >= 'A' && ch <= 'Z' { to_lower_ascii(ch) } else { ch };
        "bcdfghjklmnpqrstvwxyz".contains(low)
    }

fn looks_like_kp_prefix_at_start(x: &str) -> bool {
    let chars: Vec<char> = x.chars().collect();
    if chars.len() < 2 {
        return false;
    }

    // We need i+1, so i must be <= len-2.
    // Also cap to 48 because we check i+1 and you intended "i <= 48".
    let max_i = chars.len().saturating_sub(2).min(48);

    for i in 0..=max_i {
        let c = chars[i];
        if (c == '?' || c == '!') && chars[i + 1] == ' ' {
            // require at least one space before punct
            let mut has_space_before = false;
            for p in 0..i {
                if chars[p] == ' ' {
                    has_space_before = true;
                    break;
                }
            }
            if !has_space_before {
                return false;
            }

            // tag region mostly letters/spaces/-/'
            for p in 0..i {
                let ch = chars[p];
                if !(ch.is_ascii_alphabetic() || ch == ' ' || ch == '-' || ch == '\'') {
                    return false;
                }
            }
            return true;
        }
    }
    false
}

    fn looks_like_kt_token_tagged(x: &str, n: usize) -> bool {
        let mut tok = String::new();
        let mut good = 0usize;
        let mut total = 0usize;

        let mut finish = |tok: &mut String, good: &mut usize, total: &mut usize| {
            if tok.is_empty() {
                return;
            }
            *total += 1;
            let t = tok.clone();
            tok.clear();

            let len = t.chars().count();
            if len > n {
                let chars: Vec<char> = t.chars().collect();
                let suf = &chars[len - n..];

                let ok_digits = suf.iter().all(|&ch| ch >= '0' && ch <= '9');
                let ok_cons = suf.iter().all(|&ch| is_consonant_ascii(ch));
                if ok_digits || ok_cons {
                    *good += 1;
                }
            }
        };

        for c in x.chars() {
            if is_token_sep(c) {
                finish(&mut tok, &mut good, &mut total);
            } else {
                tok.push(c);
            }
        }
        finish(&mut tok, &mut good, &mut total);

        if total < 2 {
            return false;
        }
        (good * 100) / total >= 70
    }

    looks_like_kp_prefix_at_start(trimmed) || looks_like_kt_token_tagged(trimmed, n)
}

fn rot500kv_safe_encrypt(
    name: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    if should_use_token_tagged(name, check_chars_per_token) {
        return rot500k_token_tagged(name, password, iterations, salt, check_chars_per_token, shift_punctuation);
    }
    Ok(rot500k_prefix_tagged(name, password, iterations, salt, shift_punctuation))
}

fn rot500kv_safe_decrypt(
    obfuscated: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> VerifiedResult {
    let kt = rot500k_token_tagged_decrypt(obfuscated, password, iterations, salt, check_chars_per_token, shift_punctuation);
    if kt.ok {
        return kt;
    }
    let kp = rot500k_prefix_tagged_decrypt(obfuscated, password, iterations, salt, shift_punctuation);
    if kp.ok {
        return kp;
    }
    VerifiedResult { ok: false, value: String::new() }
}

/// ROT500KV: encrypt/decrypt auto (string-in -> string-out), refusing double-encrypt when possible.
pub fn rot500kv(
    name: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    // 0) refuse to double-encrypt
    if looks_like_rot500k_cipher(name, check_chars_per_token) {
        let r = rot500kv_safe_decrypt(name, password, iterations, salt, check_chars_per_token, shift_punctuation);
        if r.ok {
            return Ok(r.value);
        }
    }

    // 1) adaptive hardening for ENCRYPTION only
    let mut eff = check_chars_per_token.max(1);
    if name.chars().count() < 12 {
        eff = eff.max(2);
    }
    if name.chars().count() < 6 {
        eff = eff.max(3);
    }

    rot500kv_safe_encrypt(name, password, iterations, salt, eff, shift_punctuation)
}

pub fn rot500kv_decrypt(
    obfuscated: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> VerifiedResult {
    rot500kv_safe_decrypt(obfuscated, password, iterations, salt, check_chars_per_token, shift_punctuation)
}