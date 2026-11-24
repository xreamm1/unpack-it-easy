use std::{backtrace::Backtrace, fs, io::Write};

pub fn install_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let trace = Backtrace::capture();
        let thread = std::thread::current();
        let report = format!(
            "UIE {}\nos: {} / {}\nthread: {}\n{info}\n\nbacktrace status: {:?}\n{trace}\n\nSet RUST_BACKTRACE=1 or RUST_BACKTRACE=full before starting UIE to capture Rust panic backtraces. Release binaries may have limited symbols. This does not capture native access violations or forced process termination.\n",
            env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH,
            thread.name().unwrap_or("unnamed"), trace.status()
        );
        let path = crate::engine::config_path().with_file_name("crash-report.log");
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut file) = fs::File::create(&path) {
            let _ = file.write_all(report.as_bytes());
        }
        // Keep the normal stderr report, including its environment-controlled backtrace.
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore]
    fn panic_fixture() {
        install_hook();
        panic!("UIE_DIAGNOSTIC_FIXTURE");
    }

    #[test]
    fn panic_subprocess_writes_enabled_backtrace() {
        let root = std::env::temp_dir().join(format!("uie-panic-{}", std::process::id()));
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "diagnostics::tests::panic_fixture"])
            .env("LOCALAPPDATA", &root)
            .env("XDG_CONFIG_HOME", &root)
            .env("RUST_BACKTRACE", "1")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let report = fs::read_to_string(root.join("UnpackItEasy/crash-report.log")).unwrap();
        assert!(report.contains("UIE_DIAGNOSTIC_FIXTURE"));
        assert!(report.contains("backtrace status: Captured"));
        assert!(report.contains(env!("CARGO_PKG_VERSION")));
        fs::remove_dir_all(root).unwrap();
    }
}
