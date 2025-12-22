// phonoshift_app/src/main.rs

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::sync::mpsc::{self, Receiver};

use phonoshift::VerifiedResult;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Rot500k,
    Rot500kv,
    Rot500kt,
    Rot500kp,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Rot500k => "ROT500K — base (no length increase)",
            Mode::Rot500kv => "ROT500KV — verified (auto, increases output)",
            Mode::Rot500kt => "ROT500KT — token-verified (adds chars per token)",
            Mode::Rot500kp => "ROT500KP — prefix-verified (adds prefix tag)",
        }
    }

    fn is_verified(self) -> bool {
        matches!(self, Mode::Rot500kv | Mode::Rot500kt | Mode::Rot500kp)
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
            mode: Mode::Rot500k,
            check_chars: 1,
            shift_punct: true,

            input: "Vamos lá, ver se isso funciona mesmo!".to_string(),
            output: String::new(),

            password: "correct horse battery staple".to_string(),
            iterations: 500_000,
            salt: "NameFPE:v1".to_string(),

            status: "Tip: Encode writes to Output. Decode reads from Input. In verified modes, Decode can detect wrong parameters."
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
                match (job, mode) {
                    // ----------------------
                    // ENCODE
                    // ----------------------
                    (WorkerJob::Encode, Mode::Rot500k) => {
                        let enc = phonoshift::rot500k_encrypt(&inp, &pw, it, &salt, sp);
                        let dec = phonoshift::rot500k_decrypt(&enc, &pw, it, &salt, sp);
                        let ok = dec == inp;
                        WorkerResult {
                            output: enc,
                            status: format!(
                                "Encoded. Self-check (ROT500K only): {}",
                                if ok { "OK" } else { "FAILED" }
                            ),
                        }
                    }
                    (WorkerJob::Encode, Mode::Rot500kp) => WorkerResult {
                        output: phonoshift::rot500k_prefix_tagged(&inp, &pw, it, &salt, sp),
                        status: "Encoded (ROT500KP).".to_string(),
                    },
                    (WorkerJob::Encode, Mode::Rot500kt) => match phonoshift::rot500k_token_tagged(
                        &inp, &pw, it, &salt, cc, sp,
                    ) {
                        Ok(v) => WorkerResult {
                            output: v,
                            status: "Encoded (ROT500KT).".to_string(),
                        },
                        Err(e) => WorkerResult {
                            output: String::new(),
                            status: format!("Error: {e}"),
                        },
                    },
                    (WorkerJob::Encode, Mode::Rot500kv) => match phonoshift::rot500kv(
                        &inp, &pw, it, &salt, cc, sp,
                    ) {
                        Ok(v) => WorkerResult {
                            output: v,
                            status: "Encoded (ROT500KV).".to_string(),
                        },
                        Err(e) => WorkerResult {
                            output: String::new(),
                            status: format!("Error: {e}"),
                        },
                    },

                    // ----------------------
                    // DECODE
                    // ----------------------
                    (WorkerJob::Decode, Mode::Rot500k) => WorkerResult {
                        output: phonoshift::rot500k_decrypt(&inp, &pw, it, &salt, sp),
                        status: "Decoded. (No verification in ROT500K)".to_string(),
                    },
                    (WorkerJob::Decode, Mode::Rot500kp) => {
                        let VerifiedResult { ok, value } =
                            phonoshift::rot500k_prefix_tagged_decrypt(&inp, &pw, it, &salt, sp);
                        WorkerResult {
                            output: value,
                            status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                        }
                    }
                    (WorkerJob::Decode, Mode::Rot500kt) => {
                        let VerifiedResult { ok, value } = phonoshift::rot500k_token_tagged_decrypt(
                            &inp, &pw, it, &salt, cc, sp,
                        );
                        WorkerResult {
                            output: value,
                            status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                        }
                    }
                    (WorkerJob::Decode, Mode::Rot500kv) => {
                        let VerifiedResult { ok, value } =
                            phonoshift::rot500kv_decrypt(&inp, &pw, it, &salt, cc, sp);
                        WorkerResult {
                            output: value,
                            status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                        }
                    }
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
                ui.heading("ROT500K Family (aka PhonoShift) — Desktop Demo (Rust)");
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
                ui.label("PhonoShift (ROT500K) is a keyed, format-preserving obfuscation scheme using PBKDF2-HMAC keystream. Default is 500,000 iterations.");

                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    ui.label("Mode:");
                    egui::ComboBox::from_id_salt("mode_combo")
                        .selected_text(self.mode.label())
                        .show_ui(ui, |ui| {
                            for m in [Mode::Rot500k, Mode::Rot500kv, Mode::Rot500kt, Mode::Rot500kp] {
                                ui.selectable_value(&mut self.mode, m, m.label());
                            }
                        });

                    ui.add_space(14.0);
                    ui.label("Token check chars (ROT500KT / ROT500KV):");
                    ui.add(egui::DragValue::new(&mut self.check_chars).range(1..=16));
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

                ui.label("Output:");
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
                ui.heading("About the ROT500K Family");

                ui.add_space(8.0);
                ui.label("ROT500K keeps output length identical to input and preserves separators (space, -, ') and character classes (digits remain digits). It is reversible with the same password + salt + iterations.");

                ui.add_space(8.0);
                ui.label("ROT500KV is the “verified” variant. It increases output to embed a keyed verification signal so decryption can return true/false. It auto-selects between:");
                ui.add_space(4.0);
                ui.label("• ROT500KT (token verification): appends 1+ characters per token");
                ui.label("• ROT500KP (prefix verification): adds a short word-like prefix (good for short inputs)");

                ui.add_space(8.0);
                ui.label("Punctuation shifting (optional): only rotates within ¿¡ and !? (does not move punctuation positions).");
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ROT500K / PhonoShift — Rust Desktop Demo")
            .with_inner_size([980.0, 560.0]),
        ..Default::default()
    };

    eframe::run_native(
        "PhonoShift",
        options,
        Box::new(|_cc| Ok(Box::new(AppState::default()))),
    )
}