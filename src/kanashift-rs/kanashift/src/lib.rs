//! kanashift — Rust port of KanaShift demo logic (skin + JP-native + KT)
//!
//! Notes:
//! - Uses PBKDF2-HMAC-SHA256 keystream (like your demo).
//! - Uses codepoint ranges for fullwidth digits to avoid encoding/mojibake issues.
//! - Keeps kana/kanji sets as UTF-8 string literals (save this file as UTF-8).

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct VerifiedResult {
    pub ok: bool,
    pub value: String,
}

// ============================================================
// Helpers
// ============================================================

fn is_separator(ch: char) -> bool {
    matches!(ch, ' ' | '-' | '\'')
}

fn is_digit(ch: char) -> bool {
    ('0'..='9').contains(&ch)
}

/// Fullwidth digits U+FF10..U+FF19 (０..９) — avoids relying on literal chars.
fn is_fullwidth_digit(ch: char) -> bool {
    let cp = ch as u32;
    (0xFF10..=0xFF19).contains(&cp)
}

fn fw_digit_from(d: i32) -> char {
    char::from_u32(0xFF10 + (d as u32)).unwrap()
}

fn ascii_digit_from(d: i32) -> char {
    char::from_u32(('0' as u32) + (d as u32)).unwrap()
}

fn is_ascii_upper(ch: char) -> bool {
    ('A'..='Z').contains(&ch)
}

fn is_ascii_lower(ch: char) -> bool {
    ('a'..='z').contains(&ch)
}

fn to_lower_ascii(ch: char) -> char {
    if is_ascii_upper(ch) {
        ((ch as u32) | 0x20).try_into().unwrap_or(ch)
    } else {
        ch
    }
}

fn effective_shift(shift: i32, set_size: i32) -> i32 {
    if set_size <= 1 {
        return 0;
    }
    let mut m = shift % set_size;
    if m == 0 {
        m = if shift >= 0 { 1 } else { -1 };
    }
    m
}

fn rotate_in_set_no_zero(set_chars: &str, ch: char, shift: i32) -> char {
    let chars: Vec<char> = set_chars.chars().collect();
    let n = chars.len() as i32;
    if n <= 0 {
        return ch;
    }
    let idx = chars.iter().position(|&c| c == ch);
    let Some(idx) = idx else { return ch };
    let eff = effective_shift(shift, n);
    let j = (idx as i32 + eff).rem_euclid(n) as usize;
    chars[j]
}

fn rotate_in_set_allow_zero(set_chars: &str, ch: char, shift: i32) -> char {
    let chars: Vec<char> = set_chars.chars().collect();
    let n = chars.len() as i32;
    if n <= 0 {
        return ch;
    }
    let idx = chars.iter().position(|&c| c == ch);
    let Some(idx) = idx else { return ch };
    let m = shift % n;
    let j = (idx as i32 + m).rem_euclid(n) as usize;
    chars[j]
}

fn pbkdf2_keystream(password: &str, salt: &str, iterations: u32, need_bytes: usize) -> Vec<u8> {
    let need = need_bytes.max(32);
    let mut out = vec![0u8; need];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        iterations.max(1),
        &mut out,
    );
    out
}

fn hmac_sha256_bytes(key: &str, msg: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC key");
    mac.update(msg.as_bytes());
    let res = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res[..32]);
    out
}

// ============================================================
// Punctuation translation (ASCII <-> JP fullwidth)
// ============================================================

fn punct_translate(s: &str, direction: i32) -> String {
    if s.is_empty() {
        return s.to_string();
    }

    fn enc(c: char) -> char {
        match c {
            '?' => '？',
            '!' => '！',
            ',' => '、',
            '.' => '。',
            ':' => '：',
            ';' => '；',
            '(' => '（',
            ')' => '）',
            '[' => '［',
            ']' => '］',
            '{' => '｛',
            '}' => '｝',
            '"' => '＂',
            _ => c,
        }
    }
    fn dec(c: char) -> char {
        match c {
            '？' => '?',
            '！' => '!',
            '、' => ',',
            '。' => '.',
            '：' => ':',
            '；' => ';',
            '（' => '(',
            '）' => ')',
            '［' => '[',
            '］' => ']',
            '｛' => '{',
            '｝' => '}',
            '＂' => '"',
            _ => c,
        }
    }

    if direction > 0 {
        s.chars().map(enc).collect()
    } else {
        s.chars().map(dec).collect()
    }
}

// ============================================================
// Keyed JP punctuation shifting (glyph sets)
// ============================================================

const P_END: &str = "！？";
const P_MID: &str = "、。・";

fn is_shift_punct(c: char) -> bool {
    P_END.chars().any(|x| x == c) || P_MID.chars().any(|x| x == c)
}

fn punct_shift_apply(s: &str, password: &str, iterations: u32, salt: &str, direction: i32) -> String {
    if s.is_empty() {
        return s.to_string();
    }

    let need = s.chars().filter(|&c| is_shift_punct(c)).count();
    if need == 0 {
        return s.to_string();
    }

    let ks = pbkdf2_keystream(password, &format!("{salt}|PunctShiftJP:v2"), iterations, need + 64);
    let mut kpos = 0usize;

    let mut out: Vec<char> = s.chars().collect();
    for ch in out.iter_mut() {
        if !is_shift_punct(*ch) {
            continue;
        }
        let shift = (ks[kpos] as i32) * direction;
        kpos = (kpos + 1) % ks.len();

        if P_END.chars().any(|x| x == *ch) {
            *ch = rotate_in_set_no_zero(P_END, *ch, shift);
        } else {
            *ch = rotate_in_set_no_zero(P_MID, *ch, shift);
        }
    }

    out.into_iter().collect()
}

// ============================================================
// FAMILY A: “skin” (Latin/PT -> kana render), case-preserving
// ============================================================

fn skin_transform(text: &str, password: &str, iterations: u32, salt: &str, direction: i32) -> String {
    // Plain (ASCII)
    const P_VOW_LO: &str = "aeiou";
    const P_VOW_UP: &str = "AEIOU";
    const P_CON_LO: &str = "bcdfghjklmnpqrstvwxyz";
    const P_CON_UP: &str = "BCDFGHJKLMNPQRSTVWXYZ";

    // Portuguese vowels (accented)
    const P_VOW_LO_PT: &str = "áàâãäéèêëíìîïóòôõöúùûü";
    const P_VOW_UP_PT: &str = "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜ";

    // Cedilla markers (match your HTML demo)
    const C_CED_LO: char = 'ゞ'; // for 'ç'
    const C_CED_UP: char = 'ヾ'; // for 'Ç'

    // Cipher sets (lowercase -> hiragana)
    const C_VOW_LO: &str = "あいうえお"; // 5
    const C_CON_LO: &str = "さしすせそたちつてとなにぬねのはひふへほま"; // 21

    // Cipher sets (uppercase -> katakana)
    const C_VOW_UP: &str = "アイウエオ"; // 5
    const C_CON_UP: &str = "サシスセソタチツテトナニヌネノハヒフヘホマ"; // 21

    // Accented vowels (24)
    const C_ACC_LO: &str = "かきくけこみむめもやゆよらりるれろわをんゐゑゔゝ";
    const C_ACC_UP: &str = "カキクケコミムメモヤユヨラリルレロワヲンヰヱヴヽ";

    if text.is_empty() {
        return text.to_string();
    }

    let chars: Vec<char> = text.chars().collect();
    let ks = pbkdf2_keystream(password, salt, iterations, chars.len() + 64);
    let mut kpos = 0usize;

    let map_rotate =
        |plain_set: &str, cipher_set: &str, ch: char, shift: i32, dirn: i32| -> Option<char> {
            let p: Vec<char> = plain_set.chars().collect();
            let c: Vec<char> = cipher_set.chars().collect();
            if p.len() != c.len() || p.is_empty() {
                return None;
            }
            let idx = if dirn > 0 {
                p.iter().position(|&x| x == ch)
            } else {
                c.iter().position(|&x| x == ch)
            }?;
            let n = p.len() as i32;
            let j = (idx as i32 + (shift % n)).rem_euclid(n) as usize;
            Some(if dirn > 0 { c[j] } else { p[j] })
        };

    let mut out = String::with_capacity(text.len() * 2);

    for &c in &chars {
        if is_separator(c) {
            out.push(c);
            continue;
        }

        // +1 => never 0, invertible (decrypt negates)
        let shift = ((ks[kpos] as i32) + 1) * direction;
        kpos = (kpos + 1) % ks.len();

        // digits (enc => fullwidth, dec => ASCII)
        if direction > 0 {
            if is_digit(c) {
                let d = (c as i32) - ('0' as i32);
                let nd = (d + (shift % 10) + 10) % 10;
                out.push(fw_digit_from(nd));
                continue;
            }
        } else {
            if is_digit(c) || is_fullwidth_digit(c) {
                let d = if is_digit(c) {
                    (c as i32) - ('0' as i32)
                } else {
                    (c as i32) - (0xFF10 as i32)
                };
                let nd = (d + (shift % 10) + 10) % 10;
                out.push(ascii_digit_from(nd));
                continue;
            }
        }

        if direction > 0 {
            // ASCII lowercase -> hiragana
            if P_VOW_LO.contains(c) {
                out.push(map_rotate(P_VOW_LO, C_VOW_LO, c, shift, 1).unwrap_or(c));
                continue;
            }
            if P_CON_LO.contains(c) {
                out.push(map_rotate(P_CON_LO, C_CON_LO, c, shift, 1).unwrap_or(c));
                continue;
            }

            // ASCII uppercase -> katakana
            if P_VOW_UP.contains(c) {
                out.push(map_rotate(P_VOW_UP, C_VOW_UP, c, shift, 1).unwrap_or(c));
                continue;
            }
            if P_CON_UP.contains(c) {
                out.push(map_rotate(P_CON_UP, C_CON_UP, c, shift, 1).unwrap_or(c));
                continue;
            }

            // Accented vowels
            if P_VOW_LO_PT.contains(c) {
                out.push(map_rotate(P_VOW_LO_PT, C_ACC_LO, c, shift, 1).unwrap_or(c));
                continue;
            }
            if P_VOW_UP_PT.contains(c) {
                out.push(map_rotate(P_VOW_UP_PT, C_ACC_UP, c, shift, 1).unwrap_or(c));
                continue;
            }

            // Cedilla
            if c == 'ç' {
                out.push(C_CED_LO);
                continue;
            }
            if c == 'Ç' {
                out.push(C_CED_UP);
                continue;
            }

            out.push(c);
        } else {
            // Hiragana -> ASCII lowercase
            if C_VOW_LO.contains(c) {
                out.push(map_rotate(P_VOW_LO, C_VOW_LO, c, shift, -1).unwrap_or(c));
                continue;
            }
            if C_CON_LO.contains(c) {
                out.push(map_rotate(P_CON_LO, C_CON_LO, c, shift, -1).unwrap_or(c));
                continue;
            }

            // Katakana -> ASCII uppercase
            if C_VOW_UP.contains(c) {
                out.push(map_rotate(P_VOW_UP, C_VOW_UP, c, shift, -1).unwrap_or(c));
                continue;
            }
            if C_CON_UP.contains(c) {
                out.push(map_rotate(P_CON_UP, C_CON_UP, c, shift, -1).unwrap_or(c));
                continue;
            }

            // Accented vowels
            if C_ACC_LO.contains(c) {
                out.push(map_rotate(P_VOW_LO_PT, C_ACC_LO, c, shift, -1).unwrap_or(c));
                continue;
            }
            if C_ACC_UP.contains(c) {
                out.push(map_rotate(P_VOW_UP_PT, C_ACC_UP, c, shift, -1).unwrap_or(c));
                continue;
            }

            // Cedilla markers
            if c == C_CED_LO {
                out.push('ç');
                continue;
            }
            if c == C_CED_UP {
                out.push('Ç');
                continue;
            }

            out.push(c);
        }
    }

    out
}

pub fn rot500k_skin_encrypt(
    text: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let mut r = skin_transform(text, password, iterations, salt, 1);
    r = punct_translate(&r, 1);
    if shift_punctuation {
        r = punct_shift_apply(&r, password, iterations, salt, 1);
    }
    r
}

pub fn rot500k_skin_decrypt(
    text: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let mut s = text.to_string();
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, -1);
    }
    s = punct_translate(&s, -1);
    skin_transform(&s, password, iterations, salt, -1)
}

// ============================================================
// FAMILY B: JP-native (JP -> JP) + ASCII shifting
// ============================================================

fn is_kanji(c: char) -> bool {
    let cp = c as u32;
    (0x4E00..=0x9FFF).contains(&cp)
}

fn rotate_codepoint_range_no_zero(c: char, shift: i32, lo: u32, hi: u32) -> char {
    let cp = c as u32;
    if cp < lo || cp > hi {
        return c;
    }
    let n = (hi - lo + 1) as i32;
    let eff = effective_shift(shift, n);
    let idx = (cp - lo) as i32;
    let j = (idx + eff).rem_euclid(n) as u32;
    char::from_u32(lo + j).unwrap_or(c)
}

fn is_hiragana(c: char) -> bool {
    let cp = c as u32;
    (0x3041..=0x3096).contains(&cp)
}
fn is_katakana(c: char) -> bool {
    let cp = c as u32;
    (0x30A1..=0x30FA).contains(&cp)
}
fn is_stable_jp_mark(c: char) -> bool {
    matches!(c, 'ー' | '々' | 'ゝ' | 'ゞ' | 'ヽ' | 'ヾ')
}

fn build_kana_set(lo: u32, hi: u32) -> String {
    (lo..=hi).filter_map(char::from_u32).collect()
}

fn rotate_ascii_alpha_phono(c: char, shift: i32) -> char {
    const V: &str = "aeiou";
    const C: &str = "bcdfghjklmnpqrstvwxyz";

    if is_ascii_upper(c) {
        let low = to_lower_ascii(c);
        if V.contains(low) {
            return rotate_in_set_allow_zero(V, low, shift).to_ascii_uppercase();
        }
        if C.contains(low) {
            return rotate_in_set_allow_zero(C, low, shift).to_ascii_uppercase();
        }
        return c;
    }
    if is_ascii_lower(c) {
        if V.contains(c) {
            return rotate_in_set_allow_zero(V, c, shift);
        }
        if C.contains(c) {
            return rotate_in_set_allow_zero(C, c, shift);
        }
        return c;
    }
    c
}

fn jp_native_transform(text: &str, password: &str, iterations: u32, salt: &str, direction: i32) -> String {
    if text.is_empty() {
        return text.to_string();
    }

    let jp_hira = build_kana_set(0x3041, 0x3096);
    let jp_kata = build_kana_set(0x30A1, 0x30FA);

    let chars: Vec<char> = text.chars().collect();
    let ks = pbkdf2_keystream(
        password,
        &format!("{salt}|JPNative:v2|AsciiShift"),
        iterations,
        chars.len() + 64,
    );
    let mut kpos = 0usize;

    let mut out = String::with_capacity(text.len() * 2);
    for &c in &chars {
        if is_separator(c) {
            out.push(c);
            continue;
        }
        if is_stable_jp_mark(c) {
            out.push(c);
            continue;
        }

        let shift = (ks[kpos] as i32) * direction;
        kpos = (kpos + 1) % ks.len();

        // ASCII letters: PhonoShift-style
        if is_ascii_upper(c) || is_ascii_lower(c) {
            out.push(rotate_ascii_alpha_phono(c, shift));
            continue;
        }

        // digits: enc -> fullwidth; dec -> ASCII
        if direction > 0 {
            if is_digit(c) || is_fullwidth_digit(c) {
                let d = if is_digit(c) {
                    (c as i32) - ('0' as i32)
                } else {
                    (c as i32) - (0xFF10 as i32)
                };
                let eff = effective_shift(shift, 10);
                let nd = (d + eff + 10) % 10;
                out.push(fw_digit_from(nd));
                continue;
            }
        } else {
            if is_digit(c) || is_fullwidth_digit(c) {
                let d = if is_digit(c) {
                    (c as i32) - ('0' as i32)
                } else {
                    (c as i32) - (0xFF10 as i32)
                };
                let eff = effective_shift(shift, 10);
                let nd = (d + eff + 10) % 10;
                out.push(ascii_digit_from(nd));
                continue;
            }
        }

        if is_hiragana(c) {
            out.push(rotate_in_set_no_zero(&jp_hira, c, shift));
            continue;
        }
        if is_katakana(c) {
            out.push(rotate_in_set_no_zero(&jp_kata, c, shift));
            continue;
        }
        if is_kanji(c) {
            out.push(rotate_codepoint_range_no_zero(c, shift, 0x4E00, 0x9FFF));
            continue;
        }

        out.push(c);
    }

    out
}

pub fn rot500kjp_encrypt(
    text: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let mut r = jp_native_transform(text, password, iterations, salt, 1);
    r = punct_translate(&r, 1);
    if shift_punctuation {
        r = punct_shift_apply(&r, password, iterations, salt, 1);
    }
    r
}

pub fn rot500kjp_decrypt(
    text: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let mut s = text.to_string();
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, -1);
    }
    s = punct_translate(&s, -1);
    jp_native_transform(&s, password, iterations, salt, -1)
}

// ============================================================
// KT Token Verification (shared)
// ============================================================

pub fn is_token_sep(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '　' | '-' | '\'' |
        '.' | ',' | '!' | '?' | ':' | ';' |
        '。' | '、' | '！' | '？' | '：' | '；' | '・' |
        '「' | '」' | '『' | '』' |
        '（' | '）' | '［' | '］' | '｛' | '｝' |
        '\t' | '\n' | '\r'
    )
}

fn is_all_digits_anywidth(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| is_digit(c) || is_fullwidth_digit(c))
}

fn make_token_check(kind: &str, mac: &[u8; 32], check_chars_per_token: usize) -> String {
    let n = check_chars_per_token.max(1);
    let kana_chk: Vec<char> = "さしすせそたちつてとなにぬねのはひふへほま".chars().collect();

    let mut out = String::new();
    for i in 0..n {
        let b = mac[(i * 7) & 31];
        if kind == "digits" {
            out.push(fw_digit_from((b % 10) as i32));
        } else {
            out.push(kana_chk[(b as usize) % kana_chk.len()]);
        }
    }
    out
}

fn token_digest(
    password: &str,
    salt: &str,
    iterations: u32,
    token_index: usize,
    token_plain: &str,
    domain: &str,
) -> [u8; 32] {
    let msg = format!("{domain}|{salt}|{iterations}|{token_index}|{token_plain}");
    hmac_sha256_bytes(password, &msg)
}

fn build_plain_token_checks<F: Fn(&str) -> String>(
    plain: &str,
    password: &str,
    salt: &str,
    iterations: u32,
    check_chars_per_token: usize,
    domain: &str,
    norm_fn: Option<&F>,
) -> Vec<String> {
    let mut checks: Vec<String> = vec![];
    let mut tok = String::new();
    let mut tok_idx: usize = 0;

    let flush = |tok: &mut String, tok_idx: &mut usize, checks: &mut Vec<String>| {
        if tok.is_empty() {
            return;
        }
        let kind = if is_all_digits_anywidth(tok) { "digits" } else { "alpha" };
        let tnorm = if let Some(f) = norm_fn { f(tok) } else { tok.clone() };
        let mac = token_digest(password, salt, iterations, *tok_idx, &tnorm, domain);
        checks.push(make_token_check(kind, &mac, check_chars_per_token));
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
    let mut out = String::new();
    let mut tok = String::new();
    let mut tok_idx = 0usize;

    let flush =
        |tok: &mut String, out: &mut String, tok_idx: &mut usize| -> Result<(), String> {
            if tok.is_empty() {
                return Ok(());
            }
            if *tok_idx >= checks.len() {
                return Err("TokenTagged: token/check count mismatch.".to_string());
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
        return Err("TokenTagged: unused checks remain.".to_string());
    }
    Ok(out)
}

fn strip_checks_from_tagged(tagged: &str, check_chars_per_token: usize) -> Option<(String, Vec<String>)> {
    let n = check_chars_per_token.max(1);

    let mut base = String::new();
    let mut given: Vec<String> = vec![];
    let mut tok = String::new();

    let flush = |tok: &mut String, base: &mut String, given: &mut Vec<String>| -> bool {
        if tok.is_empty() {
            return true;
        }
        if tok.chars().count() <= n {
            return false;
        }
        let v: Vec<char> = tok.chars().collect();
        let base_tok: String = v[..(v.len() - n)].iter().collect();
        let chk: String = v[(v.len() - n)..].iter().collect();
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

// Domains from your HTML
pub const TOK_DOMAIN_SKIN: &str = "KanaShiftTok:v2";
pub const TOK_DOMAIN_JP: &str = "KanaShiftTokJP:v2";

// Token normalization hooks (identity in your current build)
fn norm_token_identity(s: &str) -> String {
    s.to_string()
}

// Shared KT wrappers (skin / JP)
pub fn rot500kt_skin_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    let cipher = skin_transform(plain, password, iterations, salt, 1);
    let checks = build_plain_token_checks(
        plain,
        password,
        salt,
        iterations,
        check_chars_per_token,
        TOK_DOMAIN_SKIN,
        Some(&norm_token_identity),
    );
    let mut out = attach_checks_to_cipher(&cipher, &checks)?;

    out = punct_translate(&out, 1);
    if shift_punctuation {
        out = punct_shift_apply(&out, password, iterations, salt, 1);
    }
    Ok(out)
}

pub fn rot500kt_skin_decrypt(
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
    s = punct_translate(&s, -1);

    let Some((base_cipher, given_checks)) = strip_checks_from_tagged(&s, check_chars_per_token) else {
        return VerifiedResult { ok: false, value: String::new() };
    };

    let plain = skin_transform(&base_cipher, password, iterations, salt, -1);
    let expected = build_plain_token_checks(
        &plain,
        password,
        salt,
        iterations,
        check_chars_per_token,
        TOK_DOMAIN_SKIN,
        Some(&norm_token_identity),
    );

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

pub fn rot500k_jpt_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    let cipher = jp_native_transform(plain, password, iterations, salt, 1);
    let checks = build_plain_token_checks(
        plain,
        password,
        salt,
        iterations,
        check_chars_per_token,
        TOK_DOMAIN_JP,
        Some(&norm_token_identity),
    );
    let mut out = attach_checks_to_cipher(&cipher, &checks)?;

    out = punct_translate(&out, 1);
    if shift_punctuation {
        out = punct_shift_apply(&out, password, iterations, salt, 1);
    }
    Ok(out)
}

pub fn rot500k_jpt_decrypt(
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
    s = punct_translate(&s, -1);

    let Some((base_cipher, given_checks)) = strip_checks_from_tagged(&s, check_chars_per_token) else {
        return VerifiedResult { ok: false, value: String::new() };
    };

    let plain = jp_native_transform(&base_cipher, password, iterations, salt, -1);
    let expected = build_plain_token_checks(
        &plain,
        password,
        salt,
        iterations,
        check_chars_per_token,
        TOK_DOMAIN_JP,
        Some(&norm_token_identity),
    );

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