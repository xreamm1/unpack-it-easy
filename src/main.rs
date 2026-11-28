#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
mod about;
mod analysis_views;
mod android;
mod archives;
mod background;
mod binary_compare;
mod crash_assistant;
mod cython;
mod cython_slots;
mod database;
mod debugger;
mod debugger_export;
mod detect;
mod diagnostics;
mod dynamic_analysis;
mod editor_history;
mod editor_recovery;
mod engine;
mod hex_editor;
mod indicators;
mod inspection_views;
mod language;
mod native_index;
mod native_lift;
mod plugin_manager;
mod plugins;
mod process_limits;
mod project;
mod project_diff;
mod rename;
mod report_tools;
mod retdec;
mod runtime;
mod source_save;
mod telemetry;
mod theme;
mod triage;
mod ui;
mod unpack;
mod updater;
mod workspace_chrome;
mod workspace_tools;
use engine::{Event, Settings};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, mpsc, Arc},
    thread,
};

fn headless(args: &[std::ffi::OsString]) -> i32 {
    if args.len() != 5 {
        return 2;
    }
    let settings = match fs::read_to_string(Path::new(&args[3]))
        .ok()
        .and_then(|s| serde_json::from_str::<Settings>(s.trim_start_matches('\u{feff}')).ok())
    {
        Some(value) => value,
        None => return 2,
    };
    let (tx, rx) = mpsc::channel();
    let input = PathBuf::from(&args[2]);
    thread::spawn(move || engine::job(input, settings, true, Arc::new(AtomicBool::new(false)), tx));
    let mut output = None;
    let mut analysis = None;
    let mut error = Some("worker disconnected".to_string());
    let mut log = String::new();
    let mut success = false;
    for event in rx {
        match event {
            Event::Log(text) | Event::Stage(_, text, _) => {
                log.push_str(&text);
                log.push('\n');
                let _ = fs::write(Path::new(&args[4]).with_extension("log"), &log);
            }
            Event::Output(path) => output = Some(path),
            Event::Analysis(value) => analysis = Some(value),
            Event::OfflineReady(_)
            | Event::Indicators(_)
            | Event::Progress(_)
            | Event::Problem(_)
            | Event::EndStage(_)
            | Event::Identity(_) => (),
            Event::Finished(result) => {
                match result {
                    Ok(path) => {
                        output = path;
                        error = None;
                        success = true;
                    }
                    Err(message) => error = Some(message),
                }
                break;
            }
        }
    }
    let report =
        serde_json::json!({"success":success,"output":output,"analysis":analysis,"error":error});
    if fs::write(
        Path::new(&args[4]),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .is_err()
    {
        return 2;
    }
    if success {
        0
    } else {
        1
    }
}

fn main() -> eframe::Result<()> {
    diagnostics::install_hook();
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "--analyze-trace") {
        if args.len() != 5 {
            std::process::exit(2);
        }
        let result = dynamic_analysis::import_trace(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            &AtomicBool::new(false),
        );
        if let Err(error) = &result {
            eprintln!("{error}");
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    if args.get(1).is_some_and(|arg| {
        arg == "--compare-files" || arg == "--call-graph" || arg == "--search-project"
    }) {
        let command = args[1].to_string_lossy();
        let expected = if command == "--call-graph" { 4 } else { 5 };
        if args.len() != expected {
            std::process::exit(2);
        }
        let result = (|| -> Result<(), String> {
            let cancel = AtomicBool::new(false);
            let value = match command.as_ref() {
                "--compare-files" => {
                    binary_compare::compare(Path::new(&args[2]), Path::new(&args[3]))?
                }
                "--call-graph" => {
                    serde_json::to_value(workspace_tools::graph(Path::new(&args[2]), &cancel)?)
                        .map_err(|e| e.to_string())?
                }
                _ => serde_json::to_value(workspace_tools::search(
                    Path::new(&args[2]),
                    &args[3].to_string_lossy(),
                    &[],
                    &cancel,
                )?)
                .map_err(|e| e.to_string())?,
            };
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&args[expected - 1])
                .map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())
        })();
        if let Err(error) = &result {
            let _ = fs::write(
                Path::new(&args[expected - 1]).with_extension("error.log"),
                error,
            );
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    if args.get(1).is_some_and(|a| a == "--decompile-function") {
        if args.len() != 5 {
            std::process::exit(2);
        }
        let result = (|| -> Result<PathBuf, String> {
            let settings: Settings =
                serde_json::from_slice(&fs::read(&args[4]).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let root = Path::new(&args[2])
                .canonicalize()
                .map_err(|e| e.to_string())?;
            engine::lazy_function(settings, &root, &args[3].to_string_lossy())
        })();
        if let Err(error) = &result {
            let _ = fs::write(Path::new(&args[2]).join("lazy-error.log"), error);
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    if args.get(1).is_some_and(|a| a == "--unpack") {
        if args.len() != 4 {
            std::process::exit(2);
        }
        let (tx, _rx) = mpsc::channel();
        let result = (|| -> Result<(), String> {
            let input = Path::new(&args[2])
                .canonicalize()
                .map_err(|e| e.to_string())?;
            let output = Path::new(&args[3]);
            fs::create_dir_all(output).map_err(|e| e.to_string())?;
            let output = output.canonicalize().map_err(|e| e.to_string())?;
            let analysis = detect::inspect_file(&input)?;
            unpack::automatic(
                &input,
                &analysis,
                &output,
                Settings::load().offline,
                &AtomicBool::new(false),
                &tx,
            )?;
            Ok(())
        })();
        if let Err(error) = &result {
            let _ = fs::write(Path::new(&args[3]).join("unpack-error.log"), error);
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    if args.get(1).is_some_and(|a| a == "--lift-native") {
        if args.len() != 4 {
            std::process::exit(2);
        }
        let result = native_lift::analyze(
            Path::new(&args[2]),
            Path::new(&args[3]),
            &AtomicBool::new(false),
        );
        if let Err(error) = &result {
            let _ = fs::create_dir_all(Path::new(&args[3]));
            let _ = fs::write(Path::new(&args[3]).join("native-lift-error.log"), error);
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    if args.get(1).is_some_and(|a| a == "--prepare-debugger") {
        let result = debugger::prepare("x64", Settings::load().offline);
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    if args.get(1).is_some_and(|a| a == "--prepare-offline") {
        let versions = args
            .get(2)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "all".into());
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            runtime::prepare_offline(
                Settings::load(),
                versions,
                Arc::new(AtomicBool::new(false)),
                tx,
            )
        });
        for event in rx {
            if let Event::OfflineReady(result) = event {
                std::process::exit(if result.is_ok() { 0 } else { 1 });
            }
        }
        std::process::exit(1);
    }
    if args.get(1).is_some_and(|a| a == "--export-base") {
        if args.len() != 4 {
            std::process::exit(2);
        }
        let result = project::open(Path::new(&args[2]))
            .and_then(|project| database::export(Path::new(&args[3]), &project));
        if let Err(error) = result {
            let _ = fs::write(Path::new(&args[3]).with_extension("error.log"), error);
            std::process::exit(1);
        }
        std::process::exit(0);
    }
    if args.get(1).is_some_and(|a| a == "--inspect-base") {
        if args.len() != 4 {
            std::process::exit(2);
        }
        let (value, code) = match project::open(Path::new(&args[2])) {
            Ok(project) => (serde_json::to_value(project).unwrap(), 0),
            Err(error) => (serde_json::json!({"error":error}), 1),
        };
        if fs::write(
            Path::new(&args[3]),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .is_err()
        {
            std::process::exit(2);
        }
        std::process::exit(code);
    }
    if args.get(1).is_some_and(|a| a == "--decompile") {
        std::process::exit(headless(&args));
    }
    if args.get(1).is_some_and(|a| a == "--inspect") {
        if args.len() != 4 {
            std::process::exit(2);
        }
        let (value, code) = match detect::inspect_file(Path::new(&args[2])) {
            Ok(value) => (serde_json::to_value(value).unwrap(), 0),
            Err(error) => (serde_json::json!({"error":error}), 1),
        };
        if fs::write(
            Path::new(&args[3]),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .is_err()
        {
            std::process::exit(2);
        }
        std::process::exit(code);
    }
    let input = args.get(1).map(PathBuf::from).filter(|p| p.is_file());
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/uie.png"))
        .expect("embedded UIE icon");
    let avatar = eframe::egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_icon(icon)
            .with_inner_size([1200.0, 820.0])
            .with_min_inner_size([900.0, 640.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "Unpack It Easy (UIE)",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_theme(eframe::egui::Theme::Dark);
            cc.egui_ctx.set_visuals(eframe::egui::Visuals::dark());
            let mut fonts = eframe::egui::FontDefinitions::default();
            for (name, path, family) in [
                (
                    "uie-ui",
                    "C:/Windows/Fonts/segoeui.ttf",
                    eframe::egui::FontFamily::Proportional,
                ),
                (
                    "uie-code",
                    "C:/Windows/Fonts/consola.ttf",
                    eframe::egui::FontFamily::Monospace,
                ),
            ] {
                if let Ok(bytes) = std::fs::read(path) {
                    fonts
                        .font_data
                        .insert(name.into(), eframe::egui::FontData::from_owned(bytes));
                    fonts
                        .families
                        .entry(family)
                        .or_default()
                        .insert(0, name.into());
                }
            }
            cc.egui_ctx.set_fonts(fonts);
            cc.egui_ctx.style_mut(|style| {
                use eframe::egui::{Color32, Stroke};
                style.animation_time = 0.0;
                style.text_styles.insert(
                    eframe::egui::TextStyle::Body,
                    eframe::egui::FontId::proportional(14.0),
                );
                style.text_styles.insert(
                    eframe::egui::TextStyle::Button,
                    eframe::egui::FontId::proportional(14.0),
                );
                style.spacing.button_padding = eframe::egui::vec2(8.0, 4.0);
                style.spacing.item_spacing = eframe::egui::vec2(8.0, 6.0);
                style.visuals.override_text_color = Some(Color32::WHITE);
                style.visuals.selection.bg_fill = Color32::from_gray(70);
                style.visuals.selection.stroke = Stroke::new(1.0_f32, Color32::WHITE);
                style.visuals.hyperlink_color = Color32::WHITE;
                style.visuals.warn_fg_color = Color32::from_gray(215);
                style.visuals.error_fg_color = Color32::from_rgb(245, 100, 100);
                let widgets = &mut style.visuals.widgets;
                widgets.inactive.bg_fill = Color32::from_gray(46);
                widgets.inactive.weak_bg_fill = Color32::from_gray(46);
                widgets.inactive.bg_stroke = Stroke::NONE;
                widgets.inactive.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
                widgets.hovered.bg_fill = Color32::from_gray(66);
                widgets.hovered.weak_bg_fill = Color32::from_gray(66);
                widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
                widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
                widgets.active.bg_fill = Color32::from_gray(35);
                widgets.active.weak_bg_fill = Color32::from_gray(35);
                widgets.active.bg_stroke = Stroke::NONE;
                widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
                widgets.open = widgets.inactive;
            });
            let avatar = cc.egui_ctx.load_texture(
                "uie-avatar",
                avatar,
                eframe::egui::TextureOptions::LINEAR,
            );
            let mut app = ui::Toker::new(input, avatar);
            if let Some(gl) = &cc.gl {
                match background::Background::new(gl) {
                    Ok(background) => {
                        app.background = Some(std::sync::Arc::new(background));
                        cc.egui_ctx.style_mut(|style| {
                            style.visuals.panel_fill = eframe::egui::Color32::TRANSPARENT
                        });
                    }
                    Err(error) => eprintln!("Background renderer unavailable: {error}"),
                }
            }
            cc.egui_ctx
                .style_mut(|style| style.visuals.panel_fill = eframe::egui::Color32::TRANSPARENT);
            if args.iter().any(|arg| arg == "--about") {
                app.show_about();
            }
            Ok(Box::new(app))
        }),
    );
    if let Err(error) = &result {
        let path = engine::config_path().with_file_name("startup-error.log");
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, error.to_string());
        eprintln!("UIE startup failed: {error}");
    }
    result
}
