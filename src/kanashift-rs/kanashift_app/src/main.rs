// kanashift_app/src/main.rs

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use eframe::egui::{FontData, FontDefinitions, FontFamily};

use kanashift::VerifiedResult;

use std::sync::mpsc::{self, Receiver};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Kan500kSkin,
    Kan500ktSkin,
    Kan500kJp,
    Kan500kJpt,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Kan500kSkin => "KAN500K — base “JP-looking skin” (no verification)",
            Mode::Kan500ktSkin => "KAN500KT — token-verified (adds chars per token)",
            Mode::Kan500kJp => "KAN500KJP — JP-native base (no verification)",
            Mode::Kan500kJpt => "KAN500KJPT — JP-native token-verified",
        }
    }

    fn is_verified(self) -> bool {
        matches!(self, Mode::Kan500ktSkin | Mode::Kan500kJpt)
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

    // async-ish UI
    busy: bool,
    rx: Option<Receiver<WorkerResult>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            mode: Mode::Kan500kSkin,
            check_chars: 1,
            shift_punct: true,
            input: "Testing KanaShift with mixed English content. 完了。".to_string(),
            output: String::new(),
            password: "correct horse battery staple".to_string(),
            iterations: 500_000,
            salt: "NameFPE:v1".to_string(),
            status: "Tip: Encode writes to Output. Decode reads from Input. KT modes can verify wrong parameters."
                .to_string(),

            busy: false,
            rx: None,
        }
    }
}

impl AppState {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_fonts(&cc.egui_ctx);
        Self::default()
    }

    fn start_job(&mut self, job: WorkerJob) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.status = "Working…".to_string();

        // Snapshot state (do NOT read &mut self in the worker)
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
            let res = std::panic::catch_unwind(|| match (job, mode) {
                // ----------------------
                // ENCODE
                // ----------------------
                (WorkerJob::Encode, Mode::Kan500kSkin) => WorkerResult {
                    output: kanashift::rot500k_skin_encrypt(&inp, &pw, it, &salt, sp),
                    status: "Encoded. (No verification in KAN500K)".to_string(),
                },
                (WorkerJob::Encode, Mode::Kan500ktSkin) => match kanashift::rot500kt_skin_encrypt(
                    &inp, &pw, it, &salt, cc, sp,
                ) {
                    Ok(v) => WorkerResult {
                        output: v,
                        status: "Encoded (KAN500KT).".to_string(),
                    },
                    Err(e) => WorkerResult {
                        output: String::new(),
                        status: format!("Error: {e}"),
                    },
                },
                (WorkerJob::Encode, Mode::Kan500kJp) => WorkerResult {
                    output: kanashift::rot500kjp_encrypt(&inp, &pw, it, &salt, sp),
                    status: "Encoded. (No verification in KAN500KJP)".to_string(),
                },
                (WorkerJob::Encode, Mode::Kan500kJpt) => match kanashift::rot500k_jpt_encrypt(
                    &inp, &pw, it, &salt, cc, sp,
                ) {
                    Ok(v) => WorkerResult {
                        output: v,
                        status: "Encoded (KAN500KJPT).".to_string(),
                    },
                    Err(e) => WorkerResult {
                        output: String::new(),
                        status: format!("Error: {e}"),
                    },
                },

                // ----------------------
                // DECODE
                // ----------------------
                (WorkerJob::Decode, Mode::Kan500kSkin) => WorkerResult {
                    output: kanashift::rot500k_skin_decrypt(&inp, &pw, it, &salt, sp),
                    status: "Decoded. (No verification in KAN500K)".to_string(),
                },
                (WorkerJob::Decode, Mode::Kan500ktSkin) => {
                    let VerifiedResult { ok, value } =
                        kanashift::rot500kt_skin_decrypt(&inp, &pw, it, &salt, cc, sp);
                    WorkerResult {
                        output: value,
                        status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                    }
                }
                (WorkerJob::Decode, Mode::Kan500kJp) => WorkerResult {
                    output: kanashift::rot500kjp_decrypt(&inp, &pw, it, &salt, sp),
                    status: "Decoded. (No verification in KAN500KJP)".to_string(),
                },
                (WorkerJob::Decode, Mode::Kan500kJpt) => {
                    let VerifiedResult { ok, value } =
                        kanashift::rot500k_jpt_decrypt(&inp, &pw, it, &salt, cc, sp);
                    WorkerResult {
                        output: value,
                        status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
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
        // poll worker completion
        if let Some(rx) = &self.rx {
            if let Ok(done) = rx.try_recv() {
                self.output = done.output;
                self.status = done.status;
                self.busy = false;
                self.rx = None;
            }
        }

        // keep repainting while busy so spinner animates
        if self.busy {
            ctx.request_repaint();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("KanaShift — Desktop Demo (Rust)");

            ui.add_space(6.0);
            ui.label("KanaShift (a KAN500K mod) — PBKDF2-driven format-preserving obfuscation. Default is 500,000 iterations.");

            ui.add_space(10.0);

            // Mode row
            ui.horizontal(|ui| {
                ui.label("Mode:");
                egui::ComboBox::from_id_salt("mode_combo")
                    .selected_text(self.mode.label())
                    .show_ui(ui, |ui| {
                        for m in [
                            Mode::Kan500kSkin,
                            Mode::Kan500ktSkin,
                            Mode::Kan500kJp,
                            Mode::Kan500kJpt,
                        ] {
                            ui.selectable_value(&mut self.mode, m, m.label());
                        }
                    });

                ui.add_space(14.0);
                ui.label("Token check chars (KT):");
                ui.add(egui::DragValue::new(&mut self.check_chars).range(1..=16));
            });

            ui.add_space(6.0);

            ui.checkbox(
                &mut self.shift_punct,
                "Punctuation hide (optional) — keyed shifting of JP punctuation glyphs",
            );

            ui.add_space(10.0);

            ui.label("Input (plaintext or obfuscated):");
            ui.add(
                egui::TextEdit::multiline(&mut self.input)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(8.0);

            // Params
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

            ui.add_space(10.0);

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

            ui.add_space(10.0);

            ui.label("Output:");
            ui.add(
                egui::TextEdit::multiline(&mut self.output)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(10.0);
            ui.separator();
            ui.label(&self.status);
        });
    }
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    // Put the font file here:
    // kanashift_app/assets/NotoSansCJKjp-Regular.otf
    fonts.font_data.insert(
        "jp".to_owned(),
        FontData::from_static(include_bytes!("../assets/NotoSansCJKjp-Regular.otf")),
    );

    // Prefer JP font first so kana/kanji render on non-JP Windows
    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .unwrap()
        .insert(0, "jp".to_owned());

    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .unwrap()
        .insert(0, "jp".to_owned());

    ctx.set_fonts(fonts);
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("KanaShift — Rust Desktop Demo")
            .with_inner_size([900.0, 520.0]),
        ..Default::default()
    };

    eframe::run_native(
        "KanaShift",
        options,
        Box::new(|cc| Ok(Box::new(AppState::new(cc)))),
    )
}