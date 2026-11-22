#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod archives;
mod database;
mod detect;
mod engine;
mod indicators;
mod language;
mod project;
mod rename;
mod runtime;
mod telemetry;
mod triage;
mod ui;
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
    let args: Vec<_> = std::env::args_os().collect();
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
    eframe::run_native(
        "Unpack It Easy (UIE)",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(eframe::egui::Visuals::dark());
            let avatar = cc.egui_ctx.load_texture(
                "uie-avatar",
                avatar,
                eframe::egui::TextureOptions::LINEAR,
            );
            Ok(Box::new(ui::Toker::new(input, avatar)))
        }),
    )
}
