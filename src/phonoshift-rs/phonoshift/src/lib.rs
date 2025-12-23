// phonoshift/src/lib.rs
// ROT500K2 Family / PhonoShift — Base Library (Rust port)
//
// Requires (Cargo.toml):
//   hmac = "0.12"
//   pbkdf2 = "0.12"
//   sha2 = "0.10"
//   base64 = "0.22"
//   getrandom = "0.2"
//   once_cell = "1.19"
//
// Notes (matches JS “stealth framing v4” behavior):
// - All ciphertexts are STRICT: must contain a valid stealth frame.
// - Per-message nonce is embedded in the stealth frame and mixed into PBKDF2 salt (nonce-aware keystream).
// - Verified modes derive HMAC key via PBKDF2 (domain-separated) to avoid fast password oracles.
// - ROT500K2V uses a ROT500K2V frame and then tries T-then-P verification on the payload.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

pub const NONCE_LEN: usize = 12;
pub const PAD_MAX: usize = 7;

type HmacSha256 = Hmac<Sha256>;

/// Verified result for ROT500K2V / ROT500K2T / ROT500K2P decrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedResult {
    pub ok: bool,
    pub value: String,
}

// ============================================================
// Core helpers (match JS/Python)
// ============================================================

fn is_separator(ch: char) -> bool {
    matches!(ch, ' ' | '-' | '\'')
}
fn is_digit(ch: char) -> bool {
    ('0'..='9').contains(&ch)
}
fn is_ascii_upper(ch: char) -> bool {
    ('A'..='Z').contains(&ch)
}
fn is_ascii_lower(ch: char) -> bool {
    ('a'..='z').contains(&ch)
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
    let Some(idx) = set_chars.chars().position(|x| x == ch) else { return ch };
    let idx = idx as i32;

    let eff = effective_shift(shift, n);
    let j = (idx + eff).rem_euclid(n) as usize;
    set_chars.chars().nth(j).unwrap_or(ch)
}

fn derive_keystream(password: &str, salt: &str, iterations: u32, need_bytes: usize) -> Vec<u8> {
    let need = need_bytes.max(32);
    let mut out = vec![0u8; need];
    let iters = iterations.max(1);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iters, &mut out);
    out
}

fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn make_nonce_bytes() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom(&mut n).expect("getrandom nonce");
    n
}

fn dsalt(base_salt: &str, nonce_b64u: &str, domain: &str) -> String {
    format!("{base_salt}|{domain}|n={nonce_b64u}")
}

// ============================================================
// PhonoShift core (ROT500K2 family) — nonce-aware
//   - Consonants split into common vs rare (human-ish)
// ============================================================

fn is_latin_letter(ch: char) -> bool {
    (ch as u32 >= 65 && ch as u32 <= 90) || (ch as u32 >= 97 && ch as u32 <= 122)
}

fn transform_name_like_fpe(
    s: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    nonce_b64u: &str,
    direction: i32,
) -> String {
    const VOW_LO: &str = "aeiou";

    // split consonants into human-looking vs rare
    const CON_COMMON: &str = "bcdfghklmnprstvwy";
    const CON_RARE: &str = "jqxz";

    const VOW_LO_PT: &str = "áàâãäéèêëíìîïóòôõöúùûü";
    const VOW_UP_PT: &str = "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜ";
    const CON_LO_PT: &str = "ç";
    const CON_UP_PT: &str = "Ç";

    if s.is_empty() {
        return s.to_string();
    }

    let core_salt = dsalt(salt, nonce_b64u, "Core:v2");
    let ks = derive_keystream(password, &core_salt, iterations, s.chars().count() + 64);
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

        // consonants: choose ring (common vs rare)
        if CON_COMMON.contains(lc) {
            let mut ch = rotate_in_set_no_zero(CON_COMMON, lc, shift);
            if upper {
                ch = to_upper_ascii(ch);
            }
            out.push(ch);
            continue;
        }
        if CON_RARE.contains(lc) {
            let mut ch = rotate_in_set_no_zero(CON_RARE, lc, shift);
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

// ============================================================
// Optional punctuation shifting (only ¿¡ and !?) — nonce-aware
// ============================================================

const P_OPEN: &str = "¿¡";
const P_END: &str = "!?";

fn is_shift_punct(ch: char) -> bool {
    P_OPEN.contains(ch) || P_END.contains(ch)
}

fn punct_shift_apply(
    s: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    nonce_b64u: &str,
    direction: i32,
) -> String {
    if s.is_empty() {
        return s.to_string();
    }

    let need = s.chars().filter(|&c| is_shift_punct(c)).count();
    if need == 0 {
        return s.to_string();
    }

    let punct_salt = dsalt(salt, nonce_b64u, "PunctShift:v2");
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

// ============================================================
// Stealth framing v4 (deterministic decode, no fixed signature)
// Header bytes:
//   rotByte(1) + padLen(1) + modeId(1) + nonce(12) + pad(0..7)
// Encoding:
//   - first syllable encodes rotByte raw
//   - remaining bytes encoded with +rotByte
// Decoder:
//   - reads first 3 bytes deterministically, then reads exact header bytes
//   - skips joiners, returns payload
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Rot500k2 = 0,
    Rot500k2V = 1,
    Rot500k2T = 2,
    Rot500k2P = 3,
}

fn mode_to_str(m: Mode) -> &'static str {
    match m {
        Mode::Rot500k2 => "ROT500K2",
        Mode::Rot500k2V => "ROT500K2V",
        Mode::Rot500k2T => "ROT500K2T",
        Mode::Rot500k2P => "ROT500K2P",
    }
}
fn mode_from_id(id: u8) -> Option<Mode> {
    match id {
        0 => Some(Mode::Rot500k2),
        1 => Some(Mode::Rot500k2V),
        2 => Some(Mode::Rot500k2T),
        3 => Some(Mode::Rot500k2P),
        _ => None,
    }
}

// Syllable alphabet: 256 syllables of form C V END (3 letters)
static BYTE_SYL: Lazy<Vec<[u8; 3]>> = Lazy::new(|| {
    let cset = b"bcdfghjklmnpqrstvwxyz"; // 21
    let vset = b"aeiou";                 // 5
    let end = b"nrls";                   // 4
    let mut out: Vec<[u8; 3]> = Vec::with_capacity(256);

    'outer: for &c in cset {
        for &v in vset {
            for &e in end {
                out.push([c, v, e]);
                if out.len() >= 256 {
                    break 'outer;
                }
            }
        }
    }
    out
});

static SYL_TO_BYTE: Lazy<std::collections::HashMap<[u8; 3], u8>> = Lazy::new(|| {
    let mut m = std::collections::HashMap::with_capacity(256);
    for (i, syl) in BYTE_SYL.iter().enumerate() {
        m.insert(*syl, i as u8);
    }
    m
});

fn encode_header_bytes_to_letters(bytes: &[u8]) -> Vec<u8> {
    // ASCII lower letters only (3 letters per byte)
    let rot = bytes[0];
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() * 3);

    // first byte raw
    out.extend_from_slice(&BYTE_SYL[(bytes[0] as usize) & 0xff]);

    // remaining bytes rotated by +rot
    for &b in bytes.iter().skip(1) {
        let idx = b.wrapping_add(rot);
        out.extend_from_slice(&BYTE_SYL[(idx as usize) & 0xff]);
    }
    out
}

fn decode_header_letters_to_bytes(letters_lower: &[u8], total_bytes: usize) -> Option<Vec<u8>> {
    let need_letters = total_bytes * 3;
    if letters_lower.len() < need_letters {
        return None;
    }

    let mut out = vec![0u8; total_bytes];

    // first syllable raw => rotByte
    let syl0 = [letters_lower[0], letters_lower[1], letters_lower[2]];
    let v0 = *SYL_TO_BYTE.get(&syl0)?;
    out[0] = v0;
    let rot = out[0];

    // remaining syllables unrotate by -rot
    for i in 1..total_bytes {
        let base = i * 3;
        let syl = [letters_lower[base], letters_lower[base + 1], letters_lower[base + 2]];
        let v = *SYL_TO_BYTE.get(&syl)?;
        out[i] = v.wrapping_sub(rot);
    }

    Some(out)
}

fn pick_sep(b: u8) -> &'static str {
    let r = (b as u32) % 100;
    if r < 70 { " " }
    else if r < 86 { ", " }
    else if r < 95 { " — " }
    else { "; " }
}

fn cap_first_word(s: &str) -> String {
    let mut chars = s.chars();
    let Some(first) = chars.next() else { return String::new() };
    let mut out = String::new();
    out.push(first.to_ascii_uppercase());
    out.push_str(chars.as_str());
    out
}

fn choose_word_syl(rem: usize, seed: u8) -> usize {
    let max = rem.min(3);
    if max <= 1 {
        return 1;
    }
    let r = (seed as u32) % 100;
    let mut want = if r < 15 { 1 } else if r < 60 { 2 } else { 3 };
    want = want.min(max);
    if rem > 1 && rem.saturating_sub(want) == 1 {
        // avoid leaving a 1-syllable tail when possible
        if want > 1 { want -= 1; }
        else { want = 2.min(max); }
    }
    want.max(1)
}

fn maybe_add_internal_breaks(word: &str, syl_count: usize, seed: u8) -> String {
    if syl_count < 2 {
        return word.to_string();
    }
    let r = (seed as u32) % 100;
    let do_break = if syl_count == 3 { r < 70 } else { r < 35 };
    if !do_break {
        return word.to_string();
    }
    let break_char = if (seed & 1) == 1 { '-' } else { '\'' };
    let bytes: Vec<char> = word.chars().collect();

    if syl_count == 2 {
        // 6 letters => split after 3
        let mut out = String::new();
        out.extend(bytes[..3].iter());
        out.push(break_char);
        out.extend(bytes[3..].iter());
        return out;
    }

    // syl_count == 3 => 9 letters => split after 3 or 6
    let pos = if (seed % 2) == 1 { 3 } else { 6 };
    let mut out = String::new();
    out.extend(bytes[..pos].iter());
    out.push(break_char);
    out.extend(bytes[pos..].iter());
    out
}

fn format_header_from_letters(header_letters_lower: &[u8], seed_bytes: &[u8; 32]) -> String {
    // split into syllables of 3 letters
    let mut syls: Vec<&[u8]> = Vec::new();
    for i in (0..header_letters_lower.len()).step_by(3) {
        syls.push(&header_letters_lower[i..i + 3]);
    }

    let total_syl = syls.len();
    let min_words = (total_syl + 2) / 3; // ceil(total/3)
    let max_words = total_syl;

    let mut target = 6 + (seed_bytes[0] as usize % 7); // 6..12
    target = target.clamp(min_words, max_words);

    // decide word sizes (1..3 syllables) totaling total_syl
    let mut sizes: Vec<usize> = Vec::new();
    let mut rem = total_syl;
    for wi in 0..target {
        let words_left = target - wi;
        let min_here = std::cmp::max(1, rem.saturating_sub((words_left - 1) * 3));
        let max_here = std::cmp::min(3, rem.saturating_sub((words_left - 1) * 1));

        let mut want = choose_word_syl(rem, seed_bytes[(7 + wi) & 31]);
        if want < min_here { want = min_here; }
        if want > max_here { want = max_here; }

        sizes.push(want);
        rem -= want;
    }
    while rem > 0 {
        let take = rem.min(3);
        sizes.push(take);
        rem -= take;
    }

    // build words
    let mut words: Vec<String> = Vec::new();
    let mut p = 0usize;
    for (i, &sz) in sizes.iter().enumerate() {
        let mut w_bytes: Vec<u8> = Vec::with_capacity(sz * 3);
        for _ in 0..sz {
            w_bytes.extend_from_slice(syls[p]);
            p += 1;
        }
        let w = String::from_utf8(w_bytes).unwrap_or_default();
        let w = maybe_add_internal_breaks(&w, sz, seed_bytes[(19 + i) & 31]);
        if !w.is_empty() {
            words.push(w);
        }
    }

    // join with varied separators
    let mut out = String::new();
    for (i, w) in words.into_iter().enumerate() {
        if i == 0 {
            out = cap_first_word(&w);
            continue;
        }
        let spr = if (seed_bytes[(21 + i) & 31] % 29) == 0 { "." } else { "" };
        out.push_str(spr);
        out.push_str(pick_sep(seed_bytes[(3 + i) & 31]));
        out.push_str(&w);
    }

    // end style
    match seed_bytes[2] % 5 {
        0 => out.push(' '),
        1 => out.push_str(", "),
        2 => out.push_str(" — "),
        3 => out.push_str("; "),
        _ => out.push(' '),
    }

    out
}

fn build_stealth_frame(mode: Mode, nonce: &[u8; NONCE_LEN]) -> String {
    // pad len 0..7
    let mut pad_len_b = [0u8; 1];
    getrandom(&mut pad_len_b).expect("getrandom padLen");
    let pad_len = (pad_len_b[0] as usize) % (PAD_MAX + 1);

    let mut pad = vec![0u8; pad_len];
    if pad_len > 0 {
        getrandom(&mut pad).expect("getrandom pad");
    }

    let mut rot_arr = [0u8; 1];
    getrandom(&mut rot_arr).expect("getrandom rotByte");
    let rot_byte = rot_arr[0];

    // bytes = rotByte + padLen + modeId + nonce + pad
    let total = 1 + 1 + 1 + NONCE_LEN + pad_len;
    let mut bytes = vec![0u8; total];
    bytes[0] = rot_byte;
    bytes[1] = pad_len as u8;
    bytes[2] = mode as u8;
    bytes[3..3 + NONCE_LEN].copy_from_slice(nonce);
    if pad_len > 0 {
        bytes[3 + NONCE_LEN..].copy_from_slice(&pad);
    }

    let header_letters = encode_header_bytes_to_letters(&bytes);

    // seed[32]
    let mut seed = [0u8; 32];
    for i in 0..32usize {
        let a = bytes[(i * 7) % bytes.len()];
        let b = bytes[(i * 13 + 1) % bytes.len()];
        seed[i] = a ^ b ^ ((i * 29) as u8);
    }

    format_header_from_letters(&header_letters, &seed)
}

#[derive(Debug, Clone)]
struct ParsedFrame {
    mode: Mode,
    nonce_b64u: String,
    payload: String,
}

fn is_joiner_char(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '\t' | '\n' | '\r' |
        ',' | ';' | '-' | '—'
    )
}

fn parse_stealth_frame_and_payload(s: &str) -> Option<ParsedFrame> {
    if s.len() < 12 {
        return None;
    }

    // collect letters (lowercased) until max_letters are reached
    let collect_letters = |max_letters: usize| -> (Vec<u8>, Option<usize>) {
        let mut letters: Vec<u8> = Vec::with_capacity(max_letters);
        let mut payload_start: Option<usize> = None;

        // We want a byte-index "start" AFTER we have enough letters.
        // Iterate using char_indices to get byte offsets.
        for (byte_i, ch) in s.char_indices() {
            if is_latin_letter(ch) {
                let low = if is_ascii_upper(ch) { to_lower_ascii(ch) } else { ch };
                letters.push(low as u8);
                if letters.len() == max_letters {
                    // payload starts after this char
                    payload_start = Some(byte_i + ch.len_utf8());
                    break;
                }
            }
        }
        (letters, payload_start)
    };

    // first 3 bytes => 9 letters
    let (first_letters, _) = collect_letters(9);
    if first_letters.len() < 9 {
        return None;
    }
    let first3 = decode_header_letters_to_bytes(&first_letters, 3)?;
    let pad_len = first3[1] as usize;
    let mode_id = first3[2];
    let mode = mode_from_id(mode_id)?;
    if pad_len > PAD_MAX {
        return None;
    }

    let total_bytes = 1 + 1 + 1 + NONCE_LEN + pad_len;
    let need_letters = total_bytes * 3;

    let (full_letters, payload_start_opt) = collect_letters(need_letters);
    let payload_start = payload_start_opt?;
    let header_bytes = decode_header_letters_to_bytes(&full_letters, total_bytes)?;

    // validate critical fields
    if header_bytes[1] as usize != pad_len {
        return None;
    }
    if header_bytes[2] != mode_id {
        return None;
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&header_bytes[3..3 + NONCE_LEN]);
    let nonce_b64u = b64url_encode(&nonce);

    // skip joiners between header and payload
    let mut ps = payload_start;
    while ps < s.len() {
        let ch = s[ps..].chars().next().unwrap();
        if !is_joiner_char(ch) {
            break;
        }
        ps += ch.len_utf8();
    }
    if ps >= s.len() {
        return None;
    }

    let payload = s[ps..].to_string();
    if payload.is_empty() {
        return None;
    }

    Some(ParsedFrame { mode, nonce_b64u, payload })
}

fn parse_stealth_frame_and_payload_tolerant_base(
    s: &str,
    expected_mode: Mode,
    scan_limit: usize,
) -> Option<ParsedFrame> {
    if s.is_empty() {
        return None;
    }

    // Scan by *char* offsets but slice by *byte* index (safe via char_indices).
    let mut scanned = 0usize;
    for (byte_i, _) in s.char_indices() {
        if scanned > scan_limit {
            break;
        }
        let sub = &s[byte_i..];
        if let Some(p) = parse_stealth_frame_and_payload(sub) {
            if p.mode == expected_mode {
                return Some(p);
            }
        }
        scanned += 1;
    }

    // Also try the full string if char_indices() loop didn't include index 0 for some reason
    // (it always does, but keep it defensive).
    if let Some(p) = parse_stealth_frame_and_payload(s) {
        if p.mode == expected_mode {
            return Some(p);
        }
    }

    None
}

// ============================================================
// HMAC helpers (PBKDF2-derived HMAC key) — nonce-aware
// ============================================================

fn derive_hmac_key_from_password(
    password: &str,
    base_salt: &str,
    iterations: u32,
    nonce_b64u: &str,
    domain: &str,
) -> Vec<u8> {
    let salt = dsalt(base_salt, nonce_b64u, &format!("HMACKey:{domain}"));
    derive_keystream(password, &salt, iterations, 32) // 256-bit key bytes
}

fn hmac_sha256_bytes_with_key(key: &[u8], msg: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(msg.as_bytes());
    let res = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res[..32]);
    out
}

// ============================================================
// ROT500K2T (token-verified) — nonce-aware
// ============================================================

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
        if ('a'..='z').contains(&c) {
            return false;
        }
        if ('A'..='Z').contains(&c) {
            has_letter = true;
        }
    }
    has_letter
}

const CONSET: &str = "bcdfghjklmnpqrstvwxyz";
const TOK_DOMAIN: &str = "PhonoShiftTok2";

fn token_digest(
    hmac_key: &[u8],
    salt: &str,
    iterations: u32,
    token_index: usize,
    token_plain: &str,
    nonce_b64u: &str,
) -> [u8; 32] {
    let msg = format!("{TOK_DOMAIN}|{salt}|{iterations}|n={nonce_b64u}|{token_index}|{token_plain}");
    hmac_sha256_bytes_with_key(hmac_key, &msg)
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
                ch = to_upper_ascii(ch);
            }
            out.push(ch);
        }
    }
    out
}

fn build_plain_token_checks(
    plain: &str,
    hmac_key: &[u8],
    salt: &str,
    iterations: u32,
    check_chars_per_token: usize,
    nonce_b64u: &str,
) -> Vec<String> {
    let mut checks: Vec<String> = Vec::new();
    let mut tok = String::new();
    let mut tok_idx: usize = 0;

    let mut flush = |tok: &mut String, tok_idx: &mut usize, checks: &mut Vec<String>| {
        if tok.is_empty() {
            return;
        }
        let kind = if is_all_digits_str(tok) { "digits" } else { "alpha" };
        let mac = token_digest(hmac_key, salt, iterations, *tok_idx, tok, nonce_b64u);
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
            return Err("ROT500K2T: token/check count mismatch.".to_string());
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
        return Err("ROT500K2T: unused checks remain.".to_string());
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
        let chars: Vec<char> = tok.chars().collect();
        if chars.len() <= n {
            return false;
        }
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

// ============================================================
// ROT500K2P (prefix-verified) — nonce-aware
// ============================================================

const TAG_DOMAIN: &str = "PhonoShiftTag2";
const PT_LETTERS: &str = "áàâãäéèêëíìîïóòôõöúùûüÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜçÇ";

fn only_letters_ascii_or_pt(c: char) -> bool {
    ('A'..='Z').contains(&c) || ('a'..='z').contains(&c) || PT_LETTERS.contains(c)
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
        if ('A'..='Z').contains(&c) {
            any_upper = true;
        } else if ('a'..='z').contains(&c) {
            any_lower = true;
        } else {
            any_upper = true;
            any_lower = true;
        }
    }

    if !has_letter { "title" }
    else if any_upper && !any_lower { "upper" }
    else if any_lower && !any_upper { "lower" }
    else { "title" }
}

fn apply_case_style_to_word(w: &str, style: &str) -> String {
    if w.is_empty() { return String::new(); }
    match style {
        "upper" => w.to_uppercase(),
        "lower" => w.to_lowercase(),
        _ => {
            let low = w.to_lowercase();
            let mut chars = low.chars();
            let Some(first) = chars.next() else { return String::new() };
            let mut out = String::new();
            out.push_str(&first.to_uppercase().to_string());
            out.push_str(chars.as_str());
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
    if (mac[0] % 2) == 0 { "? " } else { "! " }
}

fn build_tag_prefix_for_plaintext(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    nonce_b64u: &str,
) -> String {
    let hmac_key = derive_hmac_key_from_password(password, salt, iterations, nonce_b64u, TAG_DOMAIN);
    let msg = format!("{TAG_DOMAIN}|{salt}|{iterations}|n={nonce_b64u}|{plain}");
    let mac = hmac_sha256_bytes_with_key(&hmac_key, &msg);

    let w1 = make_pronounceable_word_from_bytes(&mac, 1, 3);
    let w2 = make_pronounceable_word_from_bytes(&mac, 4, 3);
    let mut phrase = format!("{w1} {w2}");

    let punct = pick_punct_from_bytes(&mac);
    let style = detect_case_style(plain);
    phrase = apply_case_style_to_phrase(&phrase, style);

    format!("{phrase}{punct}") // ends with space
}

fn split_tagged_prefix(tagged: &str) -> Option<(String, String)> {
    let chars: Vec<char> = tagged.chars().collect();
    if chars.len() < 3 {
        return None;
    }
    for i in 0..(chars.len() - 1) {
        if (chars[i] == '?' || chars[i] == '!') && chars[i + 1] == ' ' {
            if i + 2 >= chars.len() { return None; }
            let prefix: String = chars[..=i].iter().collect();    // includes punct, no space
            let cipher: String = chars[i + 2..].iter().collect(); // after "<punct><space>"
            if cipher.is_empty() { return None; }
            return Some((prefix, cipher));
        }
    }
    None
}

// ============================================================
// Public APIs (ROT500K2 family) — STRICT stealth frames
// ============================================================

pub fn rot500k2_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let nonce = make_nonce_bytes();
    let nonce_b64u = b64url_encode(&nonce);

    let mut payload = transform_name_like_fpe(plain, password, iterations, salt, &nonce_b64u, 1);
    if shift_punctuation {
        payload = punct_shift_apply(&payload, password, iterations, salt, &nonce_b64u, 1);
    }

    let header = build_stealth_frame(Mode::Rot500k2, &nonce);
    format!("{header}{payload}")
}

pub fn rot500k2_decrypt(
    obfuscated: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> Result<String, String> {
let u = parse_stealth_frame_and_payload_tolerant_base(obfuscated, Mode::Rot500k2, 512)
    .ok_or_else(|| "Invalid/legacy ciphertext (expected ROT500K2 stealth frame).".to_string())?;

    let mut s = u.payload;
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, &u.nonce_b64u, -1);
    }
    Ok(transform_name_like_fpe(&s, password, iterations, salt, &u.nonce_b64u, -1))
}

pub fn rot500k2t_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    let nonce = make_nonce_bytes();
    let nonce_b64u = b64url_encode(&nonce);

    let cipher = transform_name_like_fpe(plain, password, iterations, salt, &nonce_b64u, 1);

    let hmac_key = derive_hmac_key_from_password(password, salt, iterations, &nonce_b64u, TOK_DOMAIN);
    let checks = build_plain_token_checks(plain, &hmac_key, salt, iterations, check_chars_per_token, &nonce_b64u);

    let mut payload = attach_checks_to_cipher(&cipher, &checks)?;
    if shift_punctuation {
        payload = punct_shift_apply(&payload, password, iterations, salt, &nonce_b64u, 1);
    }

    let header = build_stealth_frame(Mode::Rot500k2T, &nonce);
    Ok(format!("{header}{payload}"))
}

pub fn rot500k2t_decrypt(
    obfuscated: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<VerifiedResult, String> {
    let u = parse_stealth_frame_and_payload(obfuscated)
        .ok_or_else(|| "Invalid/legacy ciphertext (expected ROT500K2T stealth frame).".to_string())?;
    if u.mode != Mode::Rot500k2T {
        return Err("Invalid/legacy ciphertext (expected ROT500K2T stealth frame).".to_string());
    }

    let mut s = u.payload;
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, &u.nonce_b64u, -1);
    }

    let Some((base_cipher, given_checks)) = strip_checks_from_tagged(&s, check_chars_per_token) else {
        return Ok(VerifiedResult { ok: false, value: String::new() });
    };

    let plain = transform_name_like_fpe(&base_cipher, password, iterations, salt, &u.nonce_b64u, -1);

    let hmac_key = derive_hmac_key_from_password(password, salt, iterations, &u.nonce_b64u, TOK_DOMAIN);
    let expected = build_plain_token_checks(&plain, &hmac_key, salt, iterations, check_chars_per_token, &u.nonce_b64u);

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

pub fn rot500k2p_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> String {
    let nonce = make_nonce_bytes();
    let nonce_b64u = b64url_encode(&nonce);

    let cipher = transform_name_like_fpe(plain, password, iterations, salt, &nonce_b64u, 1);
    let prefix = build_tag_prefix_for_plaintext(plain, password, iterations, salt, &nonce_b64u);

    let mut payload = format!("{prefix}{cipher}");
    if shift_punctuation {
        payload = punct_shift_apply(&payload, password, iterations, salt, &nonce_b64u, 1);
    }

    let header = build_stealth_frame(Mode::Rot500k2P, &nonce);
    format!("{header}{payload}")
}

pub fn rot500k2p_decrypt(
    obfuscated: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    shift_punctuation: bool,
) -> Result<VerifiedResult, String> {
    let u = parse_stealth_frame_and_payload(obfuscated)
        .ok_or_else(|| "Invalid/legacy ciphertext (expected ROT500K2P stealth frame).".to_string())?;
    if u.mode != Mode::Rot500k2P {
        return Err("Invalid/legacy ciphertext (expected ROT500K2P stealth frame).".to_string());
    }

    let mut s = u.payload;
    if shift_punctuation {
        s = punct_shift_apply(&s, password, iterations, salt, &u.nonce_b64u, -1);
    }

    let Some((prefix_given, cipher)) = split_tagged_prefix(&s) else {
        return Ok(VerifiedResult { ok: false, value: String::new() });
    };

    let plain = transform_name_like_fpe(&cipher, password, iterations, salt, &u.nonce_b64u, -1);
    let expected = build_tag_prefix_for_plaintext(&plain, password, iterations, salt, &u.nonce_b64u);
    let expected_no_space = expected[..expected.len().saturating_sub(1)].to_string();

    if expected_no_space != prefix_given {
        return Ok(VerifiedResult { ok: false, value: String::new() });
    }

    Ok(VerifiedResult { ok: true, value: plain })
}

// ROT500K2V: stealth-frame container, payload is either token-verified or prefix-verified body.
// Decrypt tries T then P.
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

pub fn rot500k2v_encrypt(
    plain: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<String, String> {
    let nonce = make_nonce_bytes();
    let nonce_b64u = b64url_encode(&nonce);

    let eff = {
        let mut e = check_chars_per_token.max(1);
        if plain.chars().count() < 12 { e = e.max(2); }
        if plain.chars().count() < 6 { e = e.max(3); }
        e
    };

    let mut payload: String;

    if should_use_token_tagged(plain, eff) {
        // build token-verified payload under the SAME nonce
        let cipher = transform_name_like_fpe(plain, password, iterations, salt, &nonce_b64u, 1);
        let hmac_key = derive_hmac_key_from_password(password, salt, iterations, &nonce_b64u, TOK_DOMAIN);
        let checks = build_plain_token_checks(plain, &hmac_key, salt, iterations, eff, &nonce_b64u);
        payload = attach_checks_to_cipher(&cipher, &checks)?;
        if shift_punctuation {
            payload = punct_shift_apply(&payload, password, iterations, salt, &nonce_b64u, 1);
        }
    } else {
        // build prefix-verified payload under the SAME nonce
        let cipher = transform_name_like_fpe(plain, password, iterations, salt, &nonce_b64u, 1);
        let prefix = build_tag_prefix_for_plaintext(plain, password, iterations, salt, &nonce_b64u);
        payload = format!("{prefix}{cipher}");
        if shift_punctuation {
            payload = punct_shift_apply(&payload, password, iterations, salt, &nonce_b64u, 1);
        }
    }

    let header = build_stealth_frame(Mode::Rot500k2V, &nonce);
    Ok(format!("{header}{payload}"))
}

pub fn rot500k2v_decrypt(
    obfuscated: &str,
    password: &str,
    iterations: u32,
    salt: &str,
    check_chars_per_token: usize,
    shift_punctuation: bool,
) -> Result<VerifiedResult, String> {
    let u = parse_stealth_frame_and_payload(obfuscated)
        .ok_or_else(|| "Invalid/legacy ciphertext (expected ROT500K2V stealth frame).".to_string())?;
    if u.mode != Mode::Rot500k2V {
        return Err("Invalid/legacy ciphertext (expected ROT500K2V stealth frame).".to_string());
    }

    // Try token-verified first
    {
        let mut s = u.payload.clone();
        if shift_punctuation {
            s = punct_shift_apply(&s, password, iterations, salt, &u.nonce_b64u, -1);
        }
        if let Some((base_cipher, given_checks)) = strip_checks_from_tagged(&s, check_chars_per_token) {
            let plain = transform_name_like_fpe(&base_cipher, password, iterations, salt, &u.nonce_b64u, -1);
            let hmac_key = derive_hmac_key_from_password(password, salt, iterations, &u.nonce_b64u, TOK_DOMAIN);
            let expected = build_plain_token_checks(&plain, &hmac_key, salt, iterations, check_chars_per_token, &u.nonce_b64u);

            if expected.len() == given_checks.len() {
                let mut ok = true;
                for (a, b) in expected.iter().zip(given_checks.iter()) {
                    if a != b { ok = false; break; }
                }
                if ok {
                    return Ok(VerifiedResult { ok: true, value: plain });
                }
            }
        }
    }

    // Try prefix-verified
    {
        let mut s = u.payload;
        if shift_punctuation {
            s = punct_shift_apply(&s, password, iterations, salt, &u.nonce_b64u, -1);
        }
        if let Some((prefix_given, cipher)) = split_tagged_prefix(&s) {
            let plain = transform_name_like_fpe(&cipher, password, iterations, salt, &u.nonce_b64u, -1);
            let expected = build_tag_prefix_for_plaintext(&plain, password, iterations, salt, &u.nonce_b64u);
            let expected_no_space = expected[..expected.len().saturating_sub(1)].to_string();
            if expected_no_space == prefix_given {
                return Ok(VerifiedResult { ok: true, value: plain });
            }
        }
    }

    Ok(VerifiedResult { ok: false, value: String::new() })
}