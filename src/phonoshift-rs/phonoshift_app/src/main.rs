// phonoshift_app/src/main.rs
//
// Updated for ROT500K2 Family (stealth-framed ciphertext, strict decode):
// - Modes renamed: ROT500K2 / ROT500K2V / ROT500K2T / ROT500K2P
// - Encode always produces stealth-framed ciphertext (human-ish prefix header)
// - Decode expects stealth-framed ciphertext; legacy ROT500K(1.x) strings will fail (by design)
// - Token check chars only apply to T / V
//
// NOTE: this file assumes your phonoshift crate exports:
//   rot500k2_encrypt, rot500k2_decrypt -> Result<String, String> for decrypt
//   rot500k2t_encrypt, rot500k2t_decrypt -> Result<VerifiedResult, String>
//   rot500k2p_encrypt, rot500k2p_decrypt -> Result<VerifiedResult, String>
//   rot500k2v_encrypt, rot500k2v_decrypt -> Result<VerifiedResult, String>

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::sync::mpsc::{self, Receiver};

use phonoshift::VerifiedResult;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Rot500k2,
    Rot500k2v,
    Rot500k2t,
    Rot500k2p,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Rot500k2 => "ROT500K2 — base (stealth-framed)",
            Mode::Rot500k2v => "ROT500K2V — verified auto (stealth-framed)",
            Mode::Rot500k2t => "ROT500K2T — token-verified (stealth-framed)",
            Mode::Rot500k2p => "ROT500K2P — prefix-verified (stealth-framed)",
        }
    }

    fn is_verified(self) -> bool {
        matches!(self, Mode::Rot500k2v | Mode::Rot500k2t | Mode::Rot500k2p)
    }

    fn wants_check_chars(self) -> bool {
        matches!(self, Mode::Rot500k2v | Mode::Rot500k2t)
    }
}

#[derive(Clone, Copy)]
enum WorkerJob {
    Encode,
    Decode,
}

struct WorkerResult {
    output: String,
    status: String,
}

struct AppState {
    mode: Mode,
    check_chars: usize,
    shift_punct: bool,

    input: String,
    output: String,

    password: String,
    iterations: u32,
    salt: String,

    status: String,
    tab: usize, // 0 demo, 1 about

    busy: bool,
    rx: Option<Receiver<WorkerResult>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            mode: Mode::Rot500k2,
            check_chars: 1,
            shift_punct: true,

            input: "Vamos lá, ver se isso funciona mesmo!".to_string(),
            output: String::new(),

            password: "correct horse battery staple".to_string(),
            iterations: 500_000,
            salt: "NameFPE:v1".to_string(),

            status: "Tip: Encode writes to Output. Decode reads from Input. ROT500K2 family expects stealth-framed ciphertext."
                .to_string(),
            tab: 0,

            busy: false,
            rx: None,
        }
    }
}

impl AppState {
    fn start_job(&mut self, job: WorkerJob) {
        if self.busy {
            return;
        }

        self.busy = true;
        self.status = "Working…".to_string();

        // Snapshot UI state for the worker thread
        let mode = self.mode;
        let it = self.iterations.max(1);
        let cc = self.check_chars.max(1);
        let salt = if self.salt.is_empty() {
            "NameFPE:v1".to_string()
        } else {
            self.salt.clone()
        };
        let pw = self.password.clone();
        let inp = self.input.clone();
        let sp = self.shift_punct;

        let (tx, rx) = mpsc::channel::<WorkerResult>();
        self.rx = Some(rx);

        std::thread::spawn(move || {
            let res = std::panic::catch_unwind(|| {
let err = |e: String| WorkerResult {
    output: String::new(),
    status: format!("Error: {e}"),
};

                match (job, mode) {
                    // ----------------------
                    // ENCODE
                    // ----------------------
                    (WorkerJob::Encode, Mode::Rot500k2) => {
                        let enc = phonoshift::rot500k2_encrypt(&inp, &pw, it, &salt, sp);
                        // Self-check (base only)
                        match phonoshift::rot500k2_decrypt(&enc, &pw, it, &salt, sp) {
                            Ok(dec) => WorkerResult {
                                output: enc,
                                status: format!(
                                    "Encoded (ROT500K2). Self-check: {}",
                                    if dec == inp { "OK" } else { "FAILED" }
                                ),
                            },
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (WorkerJob::Encode, Mode::Rot500k2p) => WorkerResult {
                        output: phonoshift::rot500k2p_encrypt(&inp, &pw, it, &salt, sp),
                        status: "Encoded (ROT500K2P).".to_string(),
                    },
                    (WorkerJob::Encode, Mode::Rot500k2t) => match phonoshift::rot500k2t_encrypt(
                        &inp, &pw, it, &salt, cc, sp,
                    ) {
                        Ok(v) => WorkerResult {
                            output: v,
                            status: "Encoded (ROT500K2T).".to_string(),
                        },
                        Err(e) => err(e.to_string()),
                    },
                    (WorkerJob::Encode, Mode::Rot500k2v) => match phonoshift::rot500k2v_encrypt(
                        &inp, &pw, it, &salt, cc, sp,
                    ) {
                        Ok(v) => WorkerResult {
                            output: v,
                            status: "Encoded (ROT500K2V).".to_string(),
                        },
                        Err(e) => err(e.to_string()),
                    },

                    // ----------------------
                    // DECODE
                    // ----------------------
                    (WorkerJob::Decode, Mode::Rot500k2) => match phonoshift::rot500k2_decrypt(
                        &inp, &pw, it, &salt, sp,
                    ) {
                        Ok(v) => WorkerResult {
                            output: v,
                            status: "Decoded. (No verification in ROT500K2)".to_string(),
                        },
                        Err(e) => err(e.to_string()),
                    },

                    (WorkerJob::Decode, Mode::Rot500k2p) => match phonoshift::rot500k2p_decrypt(
                        &inp, &pw, it, &salt, sp,
                    ) {
                        Ok(VerifiedResult { ok, value }) => WorkerResult {
                            output: value,
                            status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                        },
                        Err(e) => err(e.to_string()),
                    },

                    (WorkerJob::Decode, Mode::Rot500k2t) => match phonoshift::rot500k2t_decrypt(
                        &inp, &pw, it, &salt, cc, sp,
                    ) {
                        Ok(VerifiedResult { ok, value }) => WorkerResult {
                            output: value,
                            status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                        },
                        Err(e) => err(e.to_string()),
                    },

                    (WorkerJob::Decode, Mode::Rot500k2v) => match phonoshift::rot500k2v_decrypt(
                        &inp, &pw, it, &salt, cc, sp,
                    ) {
                        Ok(VerifiedResult { ok, value }) => WorkerResult {
                            output: value,
                            status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                        },
                        Err(e) => err(e.to_string()),
                    },
                }
            });

            let msg = match res {
                Ok(v) => v,
                Err(_) => WorkerResult {
                    output: String::new(),
                    status: "PANIC in worker thread (run debug build in a terminal with RUST_BACKTRACE=1)."
                        .to_string(),
                },
            };

            let _ = tx.send(msg);
        });
    }

    fn swap(&mut self) {
        std::mem::swap(&mut self.input, &mut self.output);
        self.status = "Swapped.".to_string();
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll background worker completion
        if let Some(rx) = &self.rx {
            if let Ok(done) = rx.try_recv() {
                self.output = done.output;
                self.status = done.status;
                self.busy = false;
                self.rx = None;
            }
        }

        // While busy, keep repainting so spinner/status updates smoothly
        if self.busy {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("ROT500K2 Family (aka PhonoShift) — Desktop Demo (Rust)");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    ui.selectable_value(&mut self.tab, 0, "Demo");
                    ui.selectable_value(&mut self.tab, 1, "About");
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.tab == 0 {
                ui.add_space(8.0);
                ui.label(
                    "PhonoShift 2.x (ROT500K2) emits a stealth-framed ciphertext (human-ish header + payload). \
                     Decrypt is strict: it expects a valid frame. Default is 500,000 PBKDF2 iterations.",
                );

                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    ui.label("Mode:");
                    egui::ComboBox::from_id_salt("mode_combo")
                        .selected_text(self.mode.label())
                        .show_ui(ui, |ui| {
                            for m in [
                                Mode::Rot500k2,
                                Mode::Rot500k2v,
                                Mode::Rot500k2t,
                                Mode::Rot500k2p,
                            ] {
                                ui.selectable_value(&mut self.mode, m, m.label());
                            }
                        });

                    ui.add_space(14.0);

                    ui.add_enabled_ui(self.mode.wants_check_chars(), |ui| {
                        ui.label("Token check chars (ROT500K2T / ROT500K2V):");
                        ui.add(egui::DragValue::new(&mut self.check_chars).range(1..=16));
                    });
                });

                ui.add_space(6.0);

                ui.checkbox(
                    &mut self.shift_punct,
                    "Shift punctuation (optional) — only ¿¡ and !? (position-preserving)",
                );

                ui.add_space(12.0);

                ui.label("Input (plaintext or obfuscated):");
                ui.add(
                    egui::TextEdit::multiline(&mut self.input)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY),
                );

                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.password).desired_width(260.0));

                    ui.add_space(10.0);
                    ui.label("PBKDF2 iterations:");
                    ui.add(egui::DragValue::new(&mut self.iterations).range(1..=5_000_000));

                    ui.add_space(10.0);
                    ui.label("Salt:");
                    ui.add(egui::TextEdit::singleline(&mut self.salt).desired_width(140.0));
                });

                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!self.busy, |ui| {
                        if ui.button("Encode").clicked() {
                            self.start_job(WorkerJob::Encode);
                        }
                        if ui.button("Decode").clicked() {
                            self.start_job(WorkerJob::Decode);
                        }
                        if ui.button("Swap ↔").clicked() {
                            self.swap();
                        }
                    });

                    if self.busy {
                        ui.add_space(10.0);
                        ui.spinner();
                        ui.label("Working…");
                    }
                });

                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    ui.label("Output:");
                    if self.mode.is_verified() {
                        ui.add_space(8.0);
                        ui.label("(verified decode returns OK/FAILED)");
                    }
                });

                ui.add(
                    egui::TextEdit::multiline(&mut self.output)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY),
                );

                ui.add_space(12.0);
                ui.separator();
                ui.label(&self.status);
            } else {
                ui.add_space(8.0);
                ui.heading("About the ROT500K2 Family");

                ui.add_space(8.0);
                ui.label(
                    "ROT500K2 keeps output length close to input (payload is format-preserving), but adds a stealth frame \
                     header so ciphertext is self-identifying and carries a per-message nonce.",
                );

                ui.add_space(8.0);
                ui.label(
                    "ROT500K2V is the verified auto mode. It increases output to embed a keyed verification signal and \
                     auto-selects between:",
                );
                ui.add_space(4.0);
                ui.label("• ROT500K2T (token verification): appends 1+ characters per token");
                ui.label("• ROT500K2P (prefix verification): adds a short word-like prefix (good for short inputs)");

                ui.add_space(8.0);
                ui.label(
                    "Security patches vs 1.x: per-message nonce mixed into PBKDF2 salt; verified modes use PBKDF2-derived \
                     HMAC keys (domain-separated).",
                );

                ui.add_space(8.0);
                ui.label("Punctuation shifting (optional): only rotates within ¿¡ and !? (does not move punctuation).");
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ROT500K2 / PhonoShift — Rust Desktop Demo")
            .with_inner_size([1000.0, 580.0]),
        ..Default::default()
    };

    eframe::run_native(
        "PhonoShift",
        options,
        Box::new(|_cc| Ok(Box::new(AppState::default()))),
    )
}