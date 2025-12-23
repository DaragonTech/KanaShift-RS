//! kanashift — Rust port of KanaShift demo logic (skin + JP-native + KT) — KAN500K2 generation
//!
//! KAN500K2 security patches (vs 1.x):
//!  1) Per-message nonce mixed into PBKDF2 salt (domain-separated) => prevents keystream reuse across messages
//!  2) Verified modes derive MAC key via PBKDF2 (domain-separated, nonce-aware) => no fast HMAC password oracle
//!  3) Stealth wire format: **kana-only**, no fixed ASCII prefix or separators
//!     - Header packs mode + nonce and is Kana64-encoded
//!     - Payload is Kana64-encoded UTF-8 bytes of the (already kana) ciphertext
//!
//! Wire format (all kana chars from KANA64):
//!   <HEADER_KANA64><PAYLOAD_KANA64>
//!   - Header is fixed length (19 chars): encodes 14 bytes = [r0, r1(masked mode), nonce(12)]
//!   - Payload is variable length (UTF-8 bytes Kana64 encoded)
//!
//! Cargo.toml deps (typical):
//!   pbkdf2 = "0.12"
//!   hmac = "0.12"
//!   sha2 = "0.10"
//!   rand = "0.8"

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct VerifiedResult {
    pub ok: bool,
    pub value: String,
}

// ============================================================
// KANA64 (kana-only "base64") helpers
// ============================================================

// IMPORTANT: must be exactly 64 chars.
const KANA64: &str =
    "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん\
     アイウエオカキクケコサシスセソタチツ";

fn kana64_tables() -> (Vec<char>, HashMap<char, u8>) {
    let chars: Vec<char> = KANA64.chars().collect();
    if chars.len() != 64 {
        panic!("KANA64 must be exactly 64 chars (got {})", chars.len());
    }
    let mut map = HashMap::with_capacity(64);
    for (i, c) in chars.iter().enumerate() {
        map.insert(*c, i as u8);
    }
    (chars, map)
}

fn kana64_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let (enc, _) = kana64_tables();

    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;

    for &b in bytes {
        acc = (acc << 8) | (b as u32);
        acc_bits += 8;

        while acc_bits >= 6 {
            acc_bits -= 6;
            let v = ((acc >> acc_bits) & 0x3F) as usize;
            out.push(enc[v]);
        }
    }

    if acc_bits > 0 {
        let v = ((acc << (6 - acc_bits)) & 0x3F) as usize;
        out.push(enc[v]);
    }

    out
}

fn kana64_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    let (_, dec) = kana64_tables();

    let mut out: Vec<u8> = Vec::with_capacity((s.chars().count() * 6 + 7) / 8);

    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;

    for c in s.chars() {
        let Some(v) = dec.get(&c) else {
            return Err(format!("Kana64 decode: invalid char {:?}", c));
        };
        acc = (acc << 6) | (*v as u32);
        acc_bits += 6;

        while acc_bits >= 8 {
            acc_bits -= 8;
            let b = ((acc >> acc_bits) & 0xFF) as u8;
            out.push(b);
        }
    }

    Ok(out)
}

// ============================================================
// KAN500K2 wire format header (kana-only, fixed size)
// ============================================================

const NONCE_LEN: usize = 12; // 96-bit
const HDR_BYTES: usize = 2 + NONCE_LEN; // r0 + r1(masked mode) + nonce
const HDR_KANA_LEN: usize = 19; // ceil(HDR_BYTES*8/6) = ceil(112/6) = 19

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Mode {
    SkinBase = 0,
    SkinT = 1,
    JpBase = 2,
    JpT = 3,
}

fn gen_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

fn pack_header(mode: Mode, nonce: &[u8; NONCE_LEN]) -> String {
    // Option B (masked mode byte):
    // - byte0 = random
    // - byte1 = (mode_bits XOR byte0)
    let mut r0 = [0u8; 1];
    OsRng.fill_bytes(&mut r0);
    let r0 = r0[0];

    let mode_bits = mode as u8;
    let b1 = mode_bits ^ r0;

    let mut hdr = [0u8; HDR_BYTES];
    hdr[0] = r0;
    hdr[1] = b1;
    hdr[2..].copy_from_slice(nonce);

    let s = kana64_encode(&hdr);
    // Defensive: this should be fixed length (19)
    if s.chars().count() != HDR_KANA_LEN {
        panic!(
            "Internal error: header kana length expected {}, got {}",
            HDR_KANA_LEN,
            s.chars().count()
        );
    }
    s
}

fn unpack_header(s: &str) -> Result<(Mode, [u8; NONCE_LEN]), String> {
    let hdr_kana: String = s.chars().take(HDR_KANA_LEN).collect();
    if hdr_kana.chars().count() != HDR_KANA_LEN {
        return Err("Ciphertext too short (missing header)".to_string());
    }

    let hdr_bytes = kana64_decode(&hdr_kana)?;
    if hdr_bytes.len() < HDR_BYTES {
        return Err("Header decode failed (too few bytes)".to_string());
    }

    let r0 = hdr_bytes[0];
    let b1 = hdr_bytes[1];
    let mode_bits = b1 ^ r0;

    let mode = match mode_bits & 0x03 {
        0 => Mode::SkinBase,
        1 => Mode::SkinT,
        2 => Mode::JpBase,
        3 => Mode::JpT,
        _ => return Err("Invalid mode bits".to_string()),
    };

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&hdr_bytes[2..2 + NONCE_LEN]);

    Ok((mode, nonce))
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

/// Fullwidth digits U+FF10..U+FF19 (０..９)
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

fn dsalt(base_salt: &str, nonce_tag: &str, domain: &str) -> String {
    // Domain-separated salt builder (nonce-aware)
    format!("{base_salt}|{domain}|n={nonce_tag}")
}

fn pbkdf2_keystream(password: &str, salt: &str, iterations: u32, need_bytes: usize) -> Vec<u8> {
    let need = need_bytes.max(32);
    let mut out = vec![0u8; need];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations.max(1), &mut out);
    out
}

fn derive_hmac_key_bytes(password: &str, base_salt: &str, iterations: u32, nonce_tag: &str, domain: &str) -> [u8; 32] {
    let mac_salt = dsalt(base_salt, nonce_tag, &format!("HMACKey:{domain}"));
    let ks = pbkdf2_keystream(password, &mac_salt, iterations, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&ks[..32]);
    out
}

fn hmac_sha256_bytes_keyed(key: &[u8; 32], msg: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
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
// Keyed JP punctuation shifting (glyph sets) — nonce-aware
// ============================================================

const P_END: &str = "！？";
const P_MID: &str = "、。・";

fn is_shift_punct(c: char) -> bool {
    P_END.chars().any(|x| x == c) || P_MID.chars().any(|x| x == c)
}

fn punct_shift_apply(s: &str, password: &str, iterations: u32, salt: &str, nonce_tag: &str, direction: i32) -> String {
    if s.is_empty() {
        return s.to_string();
    }

    let need = s.chars().filter(|&c| is_shift_punct(c)).count();
    if need == 0 {
        return s.to_string();
    }

    let ks_salt = dsalt(salt, nonce_tag, "PunctShiftJP:v2");
    let ks = pbkdf2_keystream(password, &ks_salt, iterations, need + 64);
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
// FAMILY A: “skin” (Latin/PT -> kana render), case-preserving — nonce-aware
// ============================================================

fn skin_transform(text: &str, password: &str, iterations: u32, salt: &str, nonce_tag: &str, direction: i32) -> String {
    // Plain (ASCII)
    const P_VOW_LO: &str = "aeiou";
    const P_VOW_UP: &str = "AEIOU";
    const P_CON_LO: &str = "bcdfghjklmnpqrstvwxyz";
    const P_CON_UP: &str = "BCDFGHJKLMNPQRSTVWXYZ";

    // Portuguese vowels (accented)
    const P_VOW_LO_PT: &str = "áàâãäéèêëíìîïóòôõöúùûü";
    const P_VOW_UP_PT: &str = "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜ";

    // Cedilla markers
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
    let core_salt = dsalt(salt, nonce_tag, "SkinFPE:v2");
    let ks = pbkdf2_keystream(password, &core_salt, iterations, chars.len() + 64);
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
            if P_VOW_LO.contains(c) {
                out.push(map_rotate(P_VOW_LO, C_VOW_LO, c, shift, 1).unwrap_or(c));
                continue;
            }
            if P_CON_LO.contains(c) {
                out.push(map_rotate(P_CON_LO, C_CON_LO, c, shift, 1).unwrap_or(c));
                continue;
            }
            if P_VOW_UP.contains(c) {
                out.push(map_rotate(P_VOW_UP, C_VOW_UP, c, shift, 1).unwrap_or(c));
                continue;
            }
            if P_CON_UP.contains(c) {
                out.push(map_rotate(P_CON_UP, C_CON_UP, c, shift, 1).unwrap_or(c));
                continue;
            }
            if P_VOW_LO_PT.contains(c) {
                out.push(map_rotate(P_VOW_LO_PT, C_ACC_LO, c, shift, 1).unwrap_or(c));
                continue;
            }
            if P_VOW_UP_PT.contains(c) {
                out.push(map_rotate(P_VOW_UP_PT, C_ACC_UP, c, shift, 1).unwrap_or(c));
                continue;
            }
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
            if C_VOW_LO.contains(c) {
                out.push(map_rotate(P_VOW_LO, C_VOW_LO, c, shift, -1).unwrap_or(c));
                continue;
            }
            if C_CON_LO.contains(c) {
                out.push(map_rotate(P_CON_LO, C_CON_LO, c, shift, -1).unwrap_or(c));
                continue;
            }
            if C_VOW_UP.contains(c) {
                out.push(map_rotate(P_VOW_UP, C_VOW_UP, c, shift, -1).unwrap_or(c));
                continue;
            }
            if C_CON_UP.contains(c) {
                out.push(map_rotate(P_CON_UP, C_CON_UP, c, shift, -1).unwrap_or(c));
                continue;
            }
            if C_ACC_LO.contains(c) {
                out.push(map_rotate(P_VOW_LO_PT, C_ACC_LO, c, shift, -1).unwrap_or(c));
                continue;
            }
            if C_ACC_UP.contains(c) {
                out.push(map_rotate(P_VOW_UP_PT, C_ACC_UP, c, shift, -1).unwrap_or(c));
                continue;
            }
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

// ============================================================
// FAMILY B: JP-native (JP -> JP) + ASCII shifting — nonce-aware
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

// ASCII letters in JP-native: vowels within vowels, consonants within consonants, case preserved
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

fn jp_native_transform(text: &str, password: &str, iterations: u32, salt: &str, nonce_tag: &str, direction: i32) -> String {
    if text.is_empty() {
        return text.to_string();
    }

    let jp_hira = build_kana_set(0x3041, 0x3096);
    let jp_kata = build_kana_set(0x30A1, 0x30FA);

    let chars: Vec<char> = text.chars().collect();
    let core_salt = dsalt(salt, nonce_tag, "JPNative:v2|AsciiShift");
    let ks = pbkdf2_keystream(password, &core_salt, iterations, chars.len() + 64);
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

        // ASCII letters
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

// ============================================================
// KT Token Verification (shared) — nonce-aware, PBKDF2-derived MAC key
// ============================================================

fn is_token_sep(ch: char) -> bool {
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
    mac_key: &[u8; 32],
    salt: &str,
    iterations: u32,
    _nonce_tag: &str,            // keep param to avoid refactor churn, but unused
    token_index: usize,
    token_plain: &str,
    domain: &str,
) -> [u8; 32] {
    let msg = format!("{domain}|{salt}|{iterations}|{token_index}|{token_plain}");
    hmac_sha256_bytes_keyed(mac_key, &msg)
}

fn build_plain_token_checks<F: Fn(&str) -> String>(
    plain: &str,
    mac_key: &[u8; 32],
    salt: &str,
    iterations: u32,
    nonce_tag: &str,
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
        let mac = token_digest(mac_key, salt, iterations, nonce_tag, *tok_idx, &tnorm, domain);
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

    let flush = |tok: &mut String, out: &mut String, tok_idx: &mut usize| -> Result<(), String> {
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

// Domains (bumped)
pub const TOK_DOMAIN_SKIN: &str = "KanaShiftTok2";
pub const TOK_DOMAIN_JP: &str = "KanaShiftTokJP2";

// Token normalization hooks (identity)
fn norm_token_identity(s: &str) -> String {
    s.to_string()
}

// ============================================================
// KAN500K2 public APIs (kana-only wire format)
// ============================================================

fn pack_payload(mode: Mode, nonce: &[u8; NONCE_LEN], payload_text: &str) -> String {
    let header = pack_header(mode, nonce);
    format!("{header}{payload_text}")
}

fn unpack_payload(ciphertext: &str) -> Result<(Mode, [u8; NONCE_LEN], String), String> {
    let total_chars = ciphertext.chars().count();
    if total_chars < HDR_KANA_LEN + 1 {
        return Err("Ciphertext too short".to_string());
    }

    let (mode, nonce) = unpack_header(ciphertext)?;

    let payload_text: String = ciphertext.chars().skip(HDR_KANA_LEN).collect();
    if payload_text.is_empty() {
        return Err("Ciphertext missing payload".to_string());
    }

    Ok((mode, nonce, payload_text))
}

fn unpack_payload_tolerant_base(
    s: &str,
    expected_mode: Mode,
    scan_limit: usize,
) -> Result<(Mode, [u8; NONCE_LEN], String), String> {
    let chars: Vec<char> = s.chars().collect();
    let min_len = HDR_KANA_LEN + 1;
    if chars.len() < min_len {
        return Err("Ciphertext too short".to_string());
    }

    let limit = chars.len().min(scan_limit);

    // need at least header+k64payload(>=1) after pos
    for pos in 0..=limit.saturating_sub(min_len) {
        let slice: String = chars[pos..].iter().collect();

        // strict unpack on this suffix
        if let Ok((mode, nonce, payload)) = unpack_payload(&slice) {
            if mode == expected_mode {
                return Ok((mode, nonce, payload));
            }
        }
    }

    Err("Invalid/legacy ciphertext.".to_string())
}

// Base (skin)
pub fn kan500k2_skin_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let nonce = gen_nonce();
    let nonce_tag = kana64_encode(&nonce);

    let mut r = skin_transform(plain, password, iterations, salt, &nonce_tag, 1);
    r = punct_translate(&r, 1);
    if shift_punctuation {
        r = punct_shift_apply(&r, password, iterations, salt, &nonce_tag, 1);
    }

    pack_payload(Mode::SkinBase, &nonce, &r)
}

pub fn kan500k2_skin_decrypt(
    ciphertext: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> Result<String, String> {
let (mode, nonce, payload) =
    unpack_payload_tolerant_base(ciphertext, Mode::SkinBase, 512)?;
if mode != Mode::SkinBase {
    return Err("Ciphertext mode mismatch (expected SkinBase)".to_string());
}
    let nonce_tag = kana64_encode(&nonce);

    let mut s = payload;
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, &nonce_tag, -1);
    }
    s = punct_translate(&s, -1);
    Ok(skin_transform(&s, password, iterations, salt, &nonce_tag, -1))
}

// Base (JP-native)
pub fn kan500k2_jp_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let nonce = gen_nonce();
    let nonce_tag = kana64_encode(&nonce);

    let mut r = jp_native_transform(plain, password, iterations, salt, &nonce_tag, 1);
    r = punct_translate(&r, 1);
    if shift_punctuation {
        r = punct_shift_apply(&r, password, iterations, salt, &nonce_tag, 1);
    }

    pack_payload(Mode::JpBase, &nonce, &r)
}

pub fn kan500k2_jp_decrypt(
    ciphertext: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> Result<String, String> {
let (mode, nonce, payload) =
    unpack_payload_tolerant_base(ciphertext, Mode::JpBase, 512)?;
if mode != Mode::JpBase {
    return Err("Ciphertext mode mismatch (expected JpBase)".to_string());
}
    let nonce_tag = kana64_encode(&nonce);

    let mut s = payload;
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, &nonce_tag, -1);
    }
    s = punct_translate(&s, -1);
    Ok(jp_native_transform(&s, password, iterations, salt, &nonce_tag, -1))
}

// Token-verified (skin)
pub fn kan500k2_skin_t_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    let nonce = gen_nonce();
    let nonce_tag = kana64_encode(&nonce);

    let cipher = skin_transform(plain, password, iterations, salt, &nonce_tag, 1);

    let mac_key = derive_hmac_key_bytes(password, salt, iterations, &nonce_tag, TOK_DOMAIN_SKIN);
    let checks = build_plain_token_checks(
        plain,
        &mac_key,
        salt,
        iterations,
        &nonce_tag,
        check_chars_per_token,
        TOK_DOMAIN_SKIN,
        Some(&norm_token_identity),
    );
    let mut out = attach_checks_to_cipher(&cipher, &checks)?;

    out = punct_translate(&out, 1);
    if shift_punctuation {
        out = punct_shift_apply(&out, password, iterations, salt, &nonce_tag, 1);
    }

    Ok(pack_payload(Mode::SkinT, &nonce, &out))
}

pub fn kan500k2_skin_t_decrypt(
    ciphertext: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<VerifiedResult, String> {
    let (mode, nonce, payload) = unpack_payload(ciphertext)?;
    if mode != Mode::SkinT {
        return Err("Ciphertext mode mismatch (expected SkinT)".to_string());
    }
    let nonce_tag = kana64_encode(&nonce);

    let mut s = payload;
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, &nonce_tag, -1);
    }
    s = punct_translate(&s, -1);

    let Some((base_cipher, given_checks)) = strip_checks_from_tagged(&s, check_chars_per_token) else {
        return Ok(VerifiedResult { ok: false, value: String::new() });
    };

    let plain = skin_transform(&base_cipher, password, iterations, salt, &nonce_tag, -1);

    let mac_key = derive_hmac_key_bytes(password, salt, iterations, &nonce_tag, TOK_DOMAIN_SKIN);
    let expected = build_plain_token_checks(
        &plain,
        &mac_key,
        salt,
        iterations,
        &nonce_tag,
        check_chars_per_token,
        TOK_DOMAIN_SKIN,
        Some(&norm_token_identity),
    );

    if expected.len() != given_checks.len() {
        return Ok(VerifiedResult { ok: false, value: String::new() });
    }
    for (a, b) in expected.iter().zip(given_checks.iter()) {
        if a != b {
            return Ok(VerifiedResult { ok: false, value: String::new() });
        }
    }

    Ok(VerifiedResult { ok: true, value: plain })
}

// Token-verified (JP-native)
pub fn kan500k2_jp_t_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    let nonce = gen_nonce();
    let nonce_tag = kana64_encode(&nonce);

    let cipher = jp_native_transform(plain, password, iterations, salt, &nonce_tag, 1);

    let mac_key = derive_hmac_key_bytes(password, salt, iterations, &nonce_tag, TOK_DOMAIN_JP);
    let checks = build_plain_token_checks(
        plain,
        &mac_key,
        salt,
        iterations,
        &nonce_tag,
        check_chars_per_token,
        TOK_DOMAIN_JP,
        Some(&norm_token_identity),
    );
    let mut out = attach_checks_to_cipher(&cipher, &checks)?;

    out = punct_translate(&out, 1);
    if shift_punctuation {
        out = punct_shift_apply(&out, password, iterations, salt, &nonce_tag, 1);
    }

    Ok(pack_payload(Mode::JpT, &nonce, &out))
}

pub fn kan500k2_jp_t_decrypt(
    ciphertext: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<VerifiedResult, String> {
    let (mode, nonce, payload) = unpack_payload(ciphertext)?;
    if mode != Mode::JpT {
        return Err("Ciphertext mode mismatch (expected JpT)".to_string());
    }
    let nonce_tag = kana64_encode(&nonce);

    let mut s = payload;
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, &nonce_tag, -1);
    }
    s = punct_translate(&s, -1);

    let Some((base_cipher, given_checks)) = strip_checks_from_tagged(&s, check_chars_per_token) else {
        return Ok(VerifiedResult { ok: false, value: String::new() });
    };

    let plain = jp_native_transform(&base_cipher, password, iterations, salt, &nonce_tag, -1);

    let mac_key = derive_hmac_key_bytes(password, salt, iterations, &nonce_tag, TOK_DOMAIN_JP);
    let expected = build_plain_token_checks(
        &plain,
        &mac_key,
        salt,
        iterations,
        &nonce_tag,
        check_chars_per_token,
        TOK_DOMAIN_JP,
        Some(&norm_token_identity),
    );

    if expected.len() != given_checks.len() {
        return Ok(VerifiedResult { ok: false, value: String::new() });
    }
    for (a, b) in expected.iter().zip(given_checks.iter()) {
        if a != b {
            return Ok(VerifiedResult { ok: false, value: String::new() });
        }
    }

    Ok(VerifiedResult { ok: true, value: plain })
}