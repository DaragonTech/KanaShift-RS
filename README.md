![cover-v5-optimized](./kanashift-cover.gif)

**This is a Rust port of KanaShift and PhonoShift - hardened text transmutation engines.**

# KanaShift & PhonoShift

**Reversible, format-preserving text transformation with a Japanese visual skin.
Looks Japanese. Means something else. Decodes back to the truth.**

## Overview

KanaShift and its sibling PhonoShift (ROT500K) use a PBKDF2-derived keystream with 500,000 iterations, making every password guess deliberately expensive.

This is not ROT13 repeated.
It’s a keyed design where reversal without the secret is no longer trivial.

KanaShift applies the same hardened mechanics with kana and kanji, preserving structure while shifting the surface.

For performance reasons, use release builds, as debug compilation significantly affects runtime.

## Live Demos

[![ KanaShift – JP skin ](https://img.shields.io/badge/demo-live-green)](https://syhunt.github.io/KanaShift/src/kanashift.html)

[![ PhonoShift – Latin ](https://img.shields.io/badge/demo-live-green)](https://syhunt.github.io/KanaShift/src/phonoshift.html)

----

### Example Outputs with Default Settings — “Rio de Janeiro”

| Family | Scheme      | Input            | Output                          |
|--------|-------------|------------------|---------------------------------|
| Phono  | ROT500K     | Rio de Janeiro   | Noi lo Lusaomi                  |
| Phono  | ROT500KT    | Rio de Janeiro   | Noiq lon Lusaomil               |
| Phono  | ROT500KP    | Rio de Janeiro   | Calodi Wuzifi? Noi lo Lusaomi   |
| Kana   | KAN500K     | Rio de Janeiro   | ナうう てえ テおのあえとう         |
| Kana   | KAN500KT    | Rio de Janeiro   | ナううち てえほ テおのあえとうに    |
| Kana JP| KAN500KJP   | Rio de Janeiro   | Fuu fa Sepuima                  |
| Kana JP| KAN500KJP   | リオデジャネイロ | ヅケヺヲカハルゲ                  |
| Kana JP| KAN500KJPT  | Rio de Janeiro   | Fuuの faと Sepuimaそ            |
| Kana JP| KAN500KJPT  | リオデジャネイロ | ヅケヺヲカハルゲと                |

Verified variants (KT, KJPT, KP) append additional characters to enable detection of incorrect passwords during decoding.

The output looks like Japanese text, even though its meaning is hidden.
For example, “Anna” may encode to イつてう, which Google Translate renders as “It’s good”, while only the correct password recovers the original.
Latin text becomes Japanese-looking, and Japanese text remains Japanese-looking but unreadable to native speakers.

The salt value (e.g. `NameFPE:v1`) acts as a domain and version separator rather than a per-message secret, ensuring keystreams are bound to this specific algorithm and version.

---

## What This Is (and Is Not)

KanaShift is not encryption. It’s a reversible, password-based masking system focused on format preservation, visual disguise, and recoverability.

---

## Performance & Security

A PBKDF2 - derived keystream imposes real cost per password guess (default 500K iterations), tuned for short, interactive text.
Iterations can be lowered for batch use, trading resistance for throughput.

KanaShift uses real crypto primitives but keeps output human-readable by design. Its security comes from cost and scrutiny — not obscurity.

---

## Shared Core

- Keyed and reversible (`password + salt + iterations`)
- Format-preserving (keeps `space`, `-`, `'`)
- Class-preserving rotation (no cross-class mapping, no zero-shifts)
- PBKDF2-HMAC-SHA256 keystream
- Optional verification (decode can return OK / FAILED)

---

## PhonoShift (ROT500K)

![cover-v5-optimized](./phonoshift-cover.gif)

- Stays in Latin / ASCII
- Phonetic rotation
  - vowels rotate within vowels
  - consonants rotate within consonants
  - case preserved
- Digits stay digits
- Optional punctuation swapping (role-sets, position-preserving)

**Modes:**  
`ROT500K` (base), `ROT500KT` (token-verified), `ROT500KP` (prefix-verified), `ROT500KV` (auto)

---

## KanaShift (KAN500K)

![cover-v5-optimized](./kanashift-cover.gif)

- Switches to Japanese scripts for visual disguise

**Families**
- **Skin (Latin → Kana)**  
  lowercase → hiragana, uppercase → katakana, digits → fullwidth
- **JP-native (JP → JP)**  
  kana stay kana, kanji stay kanji-like; embedded ASCII also obfuscated

**Modes:**  
`KAN500K`, `KAN500KT`, `KAN500KJP`, `KAN500KJPT`

---

## Key Differences

| Aspect         | PhonoShift (ROT500K) | KanaShift (KAN500K) |
|----------------|----------------------|----------------------|
| Visual script  | Latin / ASCII        | Japanese (kana/kanji) |
| Main goal     | Subtle scrambling    | Visual disguise      |
| Case handling | Upper/lower preserved | Uppercase via katakana |
| Digits        | ASCII digits 0–9     | Fullwidth digits ０–９ |
| JP support    | No                   | Yes                  |
| Best use      | IDs, logs, UI text   | JP text, strong masking |

---

## Usage

- **Browser:** open the HTML file in `src/` or use the hosted GitHub Pages link.
- **Rust:** build with `cargo build -p kanashift_app --release` and run the binary from `target/release/`.
- **Python:** install Gradio (`pip install gradio`) and run `python kanashift_app.py`.

### Quick Pick

- Stay Latin and same length → PhonoShift / ROT500K
- Need verification → ROT500KV
- Want strong visual disguise → KanaShift
- Mixed JP + EN text → KAN500KJP

---
Authored by the cybersecurity professional and programmer Felipe Daragon, with AI assistance.
This project is experimental, not production-ready, and is shared for learning, testing, and review.
This code has not been formally audited and should not be considered cryptographically bulletproof.
Independent review by cryptography experts is encouraged.

Released under the **a 3-clause BSD license** for research and experimental use - see the LICENSE file for details.