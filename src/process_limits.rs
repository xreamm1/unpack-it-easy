//! Resource isolation for analysis tools and their descendants. Windows jobs do
//! not restrict filesystem access, network access, or access to other processes.
use serde::{Deserialize, Serialize};
use std::process::{Child, Command};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub enabled: bool,
    pub memory_mib: u64,
    pub active_process_limit: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: supported(),
            memory_mib: 2048,
            active_process_limit: 32,
        }
    }
}

pub const fn supported() -> bool {
    cfg!(windows)
}

impl Policy {
    fn memory_bytes(&self) -> Result<usize, String> {
        if self.memory_mib == 0 || self.active_process_limit == 0 {
            return Err("analysis resource limits must be greater than zero".into());
        }
        self.memory_mib
            .checked_mul(1024 * 1024)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or_else(|| "analysis memory limit is too large for this platform".into())
    }
}

/// Call after any other creation_flags configuration and before spawn. When
/// enabled, attach must be called immediately after spawn, even on cancellation.
pub fn configure_command(command: &mut Command, policy: &Policy) -> Result<(), String> {
    if !policy.enabled {
        return Ok(());
    }
    policy.memory_bytes()?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000 | 0x0000_0004); // NO_WINDOW | SUSPENDED
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = command;
        Err("analysis resource isolation is only supported on Windows; explicitly disable it to run without limits".into())
    }
}

/// Keep alive until analysis finishes. Closing the last job handle terminates
/// remaining descendants, including after the initial tool has already exited.
pub struct Guard {
    #[cfg(windows)]
    _job: Option<std::os::windows::io::OwnedHandle>,
}

pub fn attach(child: &mut Child, policy: &Policy) -> Result<Guard, String> {
    if !policy.enabled {
        return Ok(Guard {
            #[cfg(windows)]
            _job: None,
        });
    }
    #[cfg(windows)]
    let result = windows::attach(child, policy);
    #[cfg(not(windows))]
    let result = Err("analysis resource isolation is not supported on this platform".into());
    if result.is_err() {
        // No suspended child may survive a setup error. Once assigned, closing
        // the job also terminates it; kill/wait additionally covers earlier errors.
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        ffi::c_void,
        io,
        mem::size_of,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    type Handle = *mut c_void;

    // Win32 layouts: winnt.h JOBOBJECT_EXTENDED_LIMIT_INFORMATION and
    // tlhelp32.h THREADENTRY32. SIZE_T/ULONG_PTR are pointer-sized.
    #[repr(C)]
    #[derive(Default)]
    struct BasicLimits {
        process_time: i64,
        job_time: i64,
        flags: u32,
        min_working_set: usize,
        max_working_set: usize,
        active_processes: u32,
        affinity: usize,
        priority: u32,
        scheduling: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimits {
        basic: BasicLimits,
        io: [u64; 6],
        process_memory: usize,
        job_memory: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ThreadEntry {
        size: u32,
        usage: u32,
        id: u32,
        owner: u32,
        base_priority: i32,
        delta_priority: i32,
        flags: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(job: Handle, class: i32, info: *const c_void, size: u32) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
        fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry) -> i32;
        fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry) -> i32;
        fn OpenThread(access: u32, inherit: i32, id: u32) -> Handle;
        fn ResumeThread(thread: Handle) -> u32;
    }

    fn error(operation: &str) -> String {
        format!(
            "analysis resource isolation: {operation}: {}",
            io::Error::last_os_error()
        )
    }

    fn handle(raw: Handle, operation: &str) -> Result<OwnedHandle, String> {
        if raw.is_null() || raw as isize == -1 {
            return Err(error(operation));
        }
        // SAFETY: successful Win32 calls return a new, uniquely owned handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    fn initial_thread(pid: u32) -> Result<OwnedHandle, String> {
        // Rust 1.99 cannot expose Child's main thread handle (stable in 1.100).
        // A newly created, suspended process has only its initial thread. Use
        // Microsoft's documented Toolhelp traversal and fail closed if ambiguous.
        let snapshot = handle(unsafe { CreateToolhelp32Snapshot(4, 0) }, "thread snapshot")?;
        let mut entry = ThreadEntry {
            size: size_of::<ThreadEntry>() as u32,
            ..Default::default()
        };
        if unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) } == 0 {
            return Err(error("first thread"));
        }
        let mut thread_id = None;
        loop {
            if entry.size < 16 {
                return Err("analysis resource isolation: incomplete thread entry".into());
            }
            if entry.owner == pid && thread_id.replace(entry.id).is_some() {
                return Err(
                    "analysis resource isolation: child was not suspended before initialization"
                        .into(),
                );
            }
            entry.size = size_of::<ThreadEntry>() as u32;
            if unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) } == 0 {
                if io::Error::last_os_error().raw_os_error() != Some(18) {
                    return Err(error("next thread"));
                }
                break;
            }
        }
        let id = thread_id.ok_or("analysis resource isolation: initial thread not found")?;
        handle(unsafe { OpenThread(0x0002, 0, id) }, "open initial thread")
    }

    pub(super) fn attach(child: &Child, policy: &Policy) -> Result<Guard, String> {
        let memory = policy.memory_bytes()?;
        // SAFETY: null security attributes create a non-inheritable job handle;
        // all pointers below reference correctly sized, live repr(C) structures.
        let job = handle(
            unsafe { CreateJobObjectW(ptr::null(), ptr::null()) },
            "create job",
        )?;
        let limits = ExtendedLimits {
            basic: BasicLimits {
                flags: 0x2000 | 0x0200 | 0x0008, // KILL_ON_JOB_CLOSE | JOB_MEMORY | ACTIVE_PROCESS
                active_processes: policy.active_process_limit,
                ..Default::default()
            },
            job_memory: memory,
            ..Default::default()
        };
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                9,
                &limits as *const _ as *const c_void,
                size_of::<ExtendedLimits>() as u32,
            )
        } == 0
        {
            return Err(error("set job limits"));
        }
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) } == 0 {
            return Err(error("assign suspended child"));
        }
        let thread = initial_thread(child.id())?;
        let previous_count = unsafe { ResumeThread(thread.as_raw_handle()) };
        if previous_count == u32::MAX {
            return Err(error("resume initial thread"));
        }
        if previous_count != 1 {
            return Err(
                "analysis resource isolation: unexpected initial thread suspension count".into(),
            );
        }
        Ok(Guard { _job: Some(job) })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            path::PathBuf,
            process::Stdio,
            time::{Duration, Instant},
        };

        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
            fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
            fn VirtualAlloc(
                address: Handle,
                size: usize,
                allocation_type: u32,
                protect: u32,
            ) -> Handle;
        }

        #[test]
        fn ffi_layouts_match_windows_headers() {
            assert_eq!(size_of::<ThreadEntry>(), 28);
            assert_eq!(
                size_of::<BasicLimits>(),
                if cfg!(target_pointer_width = "64") {
                    64
                } else {
                    48
                }
            );
            assert_eq!(
                size_of::<ExtendedLimits>(),
                if cfg!(target_pointer_width = "64") {
                    144
                } else {
                    112
                }
            );
        }

        fn helper_command(mode: &str, result: &PathBuf) -> Command {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "process_limits::windows::tests::owned_helper",
                    "--nocapture",
                ])
                .env("UIE_LIMIT_TEST_MODE", mode)
                .env("UIE_LIMIT_TEST_RESULT", result)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        }

        fn run_helper(mode: &str, policy: Policy) -> (Child, Guard, PathBuf) {
            let result = std::env::temp_dir().join(format!(
                "uie-limits-{}-{}-{mode}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut command = helper_command(mode, &result);
            configure_command(&mut command, &policy).unwrap();
            let mut child = command.spawn().unwrap();
            let guard = super::super::attach(&mut child, &policy).unwrap();
            (child, guard, result)
        }

        fn result_file(child: &mut Child, path: &PathBuf) -> String {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(text) = fs::read_to_string(path) {
                    if !text.is_empty() {
                        return text;
                    }
                }
                if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
                    panic!("owned helper failed to report");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        #[test]
        fn owned_helper() {
            let Ok(mode) = std::env::var("UIE_LIMIT_TEST_MODE") else {
                return;
            };
            let path = PathBuf::from(std::env::var_os("UIE_LIMIT_TEST_RESULT").unwrap());
            match mode.as_str() {
                "memory" => {
                    let mut committed = 0;
                    while committed < 256 * 1024 * 1024 {
                        if unsafe { VirtualAlloc(ptr::null_mut(), 8 * 1024 * 1024, 0x3000, 0x04) }
                            .is_null()
                        {
                            break;
                        }
                        committed += 8 * 1024 * 1024;
                    }
                    fs::write(path, committed.to_string()).unwrap();
                }
                "process-cap" => {
                    let blocked = helper_command("leaf", &path).spawn().is_err();
                    fs::write(path, blocked.to_string()).unwrap();
                }
                "descendant" => {
                    // The parent job test intentionally kills this descendant after this helper exits.
                    #[allow(clippy::zombie_processes)]
                    let child = helper_command("leaf", &path).spawn().unwrap();
                    fs::write(path, child.id().to_string()).unwrap();
                }
                "leaf" => {}
                _ => panic!("unknown owned helper mode"),
            }
            std::thread::sleep(Duration::from_secs(30));
        }

        #[test]
        fn child_does_not_execute_before_attachment() {
            let path = std::env::temp_dir().join(format!(
                "uie-suspended-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut command = helper_command("memory", &path);
            let policy = Policy::default();
            configure_command(&mut command, &policy).unwrap();
            let mut child = command.spawn().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let ran_early = path.exists();
            // Invalid policy makes attachment fail before any resumption. It
            // must also terminate and reap the suspended child.
            assert!(super::super::attach(
                &mut child,
                &Policy {
                    memory_mib: 0,
                    ..policy
                }
            )
            .is_err());
            assert!(child.try_wait().unwrap().is_some());
            assert!(!ran_early && !path.exists());
        }

        #[test]
        fn job_memory_limit_rejects_excess_commit() {
            let (mut child, guard, path) = run_helper(
                "memory",
                Policy {
                    memory_mib: 128,
                    ..Default::default()
                },
            );
            let committed: usize = result_file(&mut child, &path).parse().unwrap();
            drop(guard);
            child.wait().unwrap();
            fs::remove_file(path).unwrap();
            assert!(committed > 0 && committed < 128 * 1024 * 1024);
        }

        #[test]
        fn job_process_limit_blocks_descendants() {
            let (mut child, guard, path) = run_helper(
                "process-cap",
                Policy {
                    active_process_limit: 1,
                    ..Default::default()
                },
            );
            let blocked = result_file(&mut child, &path);
            drop(guard);
            child.wait().unwrap();
            fs::remove_file(path).unwrap();
            assert_eq!(blocked, "true");
        }

        #[test]
        fn dropping_job_terminates_owned_descendant() {
            let (mut child, guard, path) = run_helper("descendant", Policy::default());
            let pid: u32 = result_file(&mut child, &path).parse().unwrap();
            let descendant = handle(
                unsafe { OpenProcess(0x0010_0000, 0, pid) },
                "open test descendant",
            )
            .unwrap();
            drop(guard);
            child.wait().unwrap();
            assert_eq!(
                unsafe { WaitForSingleObject(descendant.as_raw_handle(), 5000) },
                0
            );
            fs::remove_file(path).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_invalid_limits() {
        let policy: Policy = serde_json::from_str("{}").unwrap();
        assert_eq!(policy.enabled, supported());
        assert_eq!(policy.memory_mib, 2048);
        assert_eq!(policy.active_process_limit, 32);
        assert!(Policy {
            memory_mib: 0,
            ..Default::default()
        }
        .memory_bytes()
        .is_err());
        assert!(Policy {
            memory_mib: u64::MAX,
            ..Default::default()
        }
        .memory_bytes()
        .is_err());
        assert!(Policy {
            active_process_limit: 0,
            ..Default::default()
        }
        .memory_bytes()
        .is_err());
    }
}
