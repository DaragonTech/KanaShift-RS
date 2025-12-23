// kanashift_app/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use eframe::egui::{FontData, FontDefinitions, FontFamily};
use std::sync::mpsc::{self, Receiver};

use kanashift::VerifiedResult;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Kan500k2Skin,
    Kan500k2SkinT,
    Kan500k2Jp,
    Kan500k2JpT,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Kan500k2Skin => "KAN500K2 — skin base (kana-only header; no verification)",
            Mode::Kan500k2SkinT => "KAN500K2T — skin token-verified (kana-only header)",
            Mode::Kan500k2Jp => "KAN500K2JP — JP-native base (kana-only header; no verification)",
            Mode::Kan500k2JpT => "KAN500K2JPT — JP-native token-verified (kana-only header)",
        }
    }

    fn is_verified(self) -> bool {
        matches!(self, Mode::Kan500k2SkinT | Mode::Kan500k2JpT)
    }

    fn expects_k2(self) -> bool {
        true
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
            mode: Mode::Kan500k2Skin,
            check_chars: 1,
            shift_punct: true,
            input: "Testing KanaShift with mixed English content. 完了。".to_string(),
            output: String::new(),
            password: "correct horse battery staple".to_string(),
            iterations: 500_000,
            salt: "NameFPE:v1".to_string(),
            status: "Tip: Encode writes to Output. Decode reads from Input. T modes can verify wrong parameters."
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
                // ENCODE (KAN500K2)
                // ----------------------
                (WorkerJob::Encode, Mode::Kan500k2Skin) => WorkerResult {
                    output: kanashift::kan500k2_skin_encrypt(&inp, &pw, it, &salt, sp),
                    status: "Encoded. (No verification in KAN500K2)".to_string(),
                },
                (WorkerJob::Encode, Mode::Kan500k2SkinT) => match kanashift::kan500k2_skin_t_encrypt(
                    &inp, &pw, it, &salt, cc, sp,
                ) {
                    Ok(v) => WorkerResult {
                        output: v,
                        status: "Encoded (KAN500K2T).".to_string(),
                    },
                    Err(e) => WorkerResult {
                        output: String::new(),
                        status: format!("Error: {e}"),
                    },
                },
                (WorkerJob::Encode, Mode::Kan500k2Jp) => WorkerResult {
                    output: kanashift::kan500k2_jp_encrypt(&inp, &pw, it, &salt, sp),
                    status: "Encoded. (No verification in KAN500K2JP)".to_string(),
                },
                (WorkerJob::Encode, Mode::Kan500k2JpT) => match kanashift::kan500k2_jp_t_encrypt(
                    &inp, &pw, it, &salt, cc, sp,
                ) {
                    Ok(v) => WorkerResult {
                        output: v,
                        status: "Encoded (KAN500K2JPT).".to_string(),
                    },
                    Err(e) => WorkerResult {
                        output: String::new(),
                        status: format!("Error: {e}"),
                    },
                },

                // ----------------------
                // DECODE (KAN500K2)
                // ----------------------
                (WorkerJob::Decode, Mode::Kan500k2Skin) => match kanashift::kan500k2_skin_decrypt(&inp, &pw, it, &salt, sp)
                {
                    Ok(v) => WorkerResult {
                        output: v,
                        status: "Decoded. (No verification in KAN500K2)".to_string(),
                    },
                    Err(e) => WorkerResult {
                        output: String::new(),
                        status: format!("Error: {e}"),
                    },
                },
                (WorkerJob::Decode, Mode::Kan500k2SkinT) => match kanashift::kan500k2_skin_t_decrypt(
                    &inp, &pw, it, &salt, cc, sp,
                ) {
                    Ok(VerifiedResult { ok, value }) => WorkerResult {
                        output: value,
                        status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                    },
                    Err(e) => WorkerResult {
                        output: String::new(),
                        status: format!("Error: {e}"),
                    },
                },
                (WorkerJob::Decode, Mode::Kan500k2Jp) => match kanashift::kan500k2_jp_decrypt(&inp, &pw, it, &salt, sp) {
                    Ok(v) => WorkerResult {
                        output: v,
                        status: "Decoded. (No verification in KAN500K2JP)".to_string(),
                    },
                    Err(e) => WorkerResult {
                        output: String::new(),
                        status: format!("Error: {e}"),
                    },
                },
                (WorkerJob::Decode, Mode::Kan500k2JpT) => match kanashift::kan500k2_jp_t_decrypt(
                    &inp, &pw, it, &salt, cc, sp,
                ) {
                    Ok(VerifiedResult { ok, value }) => WorkerResult {
                        output: value,
                        status: format!("Decoded. Verified: {}", if ok { "OK" } else { "FAILED" }),
                    },
                    Err(e) => WorkerResult {
                        output: String::new(),
                        status: format!("Error: {e}"),
                    },
                },
            });

            let msg = match res {
                Ok(v) => v,
                Err(_) => WorkerResult {
                    output: String::new(),
                    status: "PANIC in worker thread (debug build + RUST_BACKTRACE=1).".to_string(),
                },
            };

            let _ = tx.send(msg);
        });
    }

    fn swap(&mut self) {
        std::mem::swap(&mut self.input, &mut self.output);
        self.status = "Swapped.".to_string();
    }

    fn header_preview(&self) -> String {
        // KAN500K2 kana-only header is always 19 kana chars.
        // We avoid parsing here; just show the first N chars if available.
        let s = self.output.trim();
        let head: String = s.chars().take(19).collect();
        if head.is_empty() {
            "—".to_string()
        } else if s.chars().count() < 19 {
            format!("{head}… (incomplete)")
        } else {
            head
        }
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
            ui.heading("KanaShift — Desktop Demo (Rust, KAN500K2)");

            ui.add_space(6.0);
            ui.label("KAN500K2 patch: per-message nonce + PBKDF2-derived MAC key (T modes) + kana-only stealth header (no fixed ASCII prefix/separators).");

            ui.add_space(10.0);

            // Mode row
            ui.horizontal(|ui| {
                ui.label("Mode:");
                egui::ComboBox::from_id_salt("mode_combo")
                    .selected_text(self.mode.label())
                    .show_ui(ui, |ui| {
                        for m in [
                            Mode::Kan500k2Skin,
                            Mode::Kan500k2SkinT,
                            Mode::Kan500k2Jp,
                            Mode::Kan500k2JpT,
                        ] {
                            ui.selectable_value(&mut self.mode, m, m.label());
                        }
                    });

                ui.add_space(14.0);

                ui.add_enabled_ui(self.mode.is_verified(), |ui| {
                    ui.label("Token check chars (T):");
                    ui.add(egui::DragValue::new(&mut self.check_chars).range(1..=16));
                });

                if !self.mode.is_verified() {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("—").weak());
                }
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

            ui.add_space(8.0);

            // Small K2 header hint (stealth header preview)
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Stealth header (first 19 chars):").weak());
                ui.monospace(self.header_preview());
            });

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
            .with_title("KanaShift — Rust Desktop Demo (KAN500K2)")
            .with_inner_size([920.0, 560.0]),
        ..Default::default()
    };

    eframe::run_native(
        "KanaShift",
        options,
        Box::new(|cc| Ok(Box::new(AppState::new(cc)))),
    )
}