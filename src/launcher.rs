//! Container launcher orchestration
//!
//! This module orchestrates the container creation process:
//! 1. Parse and validate CLI arguments
//! 2. Create cgroup for resource limits
//! 3. Unshare namespaces for isolation
//! 4. Fork child process
//! 5. Child: Configure namespaces, drop capabilities, apply seccomp, execute command
//! 6. Parent: Attach child to cgroup, wait for completion, cleanup
//!
//! Note: Full container execution is only supported on Linux.

use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[cfg(target_os = "linux")]
use nix::sys::wait::{waitpid, WaitStatus};
#[cfg(target_os = "linux")]
use nix::unistd::{execvp, fork, ForkResult};

use crate::cli::RunArgs;
use crate::error::{NucleusError, Result};
#[cfg(target_os = "linux")]
use crate::namespace::NamespaceManager;
use crate::security::{SecurityManager, SecurityProfile};

/// Run a container with the given arguments
#[cfg(target_os = "linux")]
pub fn run_container(args: &RunArgs) -> Result<()> {
    info!("Starting container with args: {:?}", args);

    // Validate arguments
    validate_args(args)?;

    // Validate runtime option (must be 'native' or 'gvisor')
    validate_runtime(&args.runtime)?;

    // Parse memory limit
    let memory_bytes = args.memory_bytes()
        .map_err(NucleusError::MemoryParse)?;

    // Generate container ID
    let container_id = generate_container_id();
    info!("Container ID: {}", container_id);

    // Check runtime and handle gVisor
    let use_gvisor = args.runtime == "gvisor";
    if use_gvisor {
        info!("gVisor runtime requested");
        if !crate::security::is_gvisor_available() {
            return Err(NucleusError::GvisorNotFound(
                "runsc not found in PATH. Install gVisor from https://gvisor.dev/docs/user_guide/install/".to_string()
            ));
        }
        info!("gVisor runtime (runsc) found, delegating to gVisor executor");

        // Execute with gVisor
        let exit_code = crate::gvisor::run_with_gvisor(&container_id, args, memory_bytes)?;

        if exit_code != 0 {
            return Err(NucleusError::ChildExit(exit_code));
        }

        info!("Container execution completed successfully via gVisor");
        return Ok(());
    }

    // Native runtime execution (fork + exec)

    // Create cgroup
    let cgroup = crate::cgroup::Cgroup::create(&container_id)?;

    // Configure cgroup with resource limits
    let cgroup_config = crate::cgroup::CgroupConfig::new(memory_bytes, args.cpus);
    cgroup.configure(&cgroup_config)?;

    // Create security manager
    let mut security_manager = SecurityManager::default_profile(use_gvisor);
    security_manager.prepare()?;

    // Create namespace manager
    let namespace_manager = NamespaceManager::new(args.hostname.clone());
    info!("Namespace types: {}", crate::namespace::describe_flags(namespace_manager.flags()));

    // Unshare namespaces
    // Note: For PID namespace, unshare affects child processes
    namespace_manager.unshare_namespaces()?;

    // Fork child process
    let child_pid = match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            info!("Forked child process with PID: {}", child);
            child
        }
        Ok(ForkResult::Child) => {
            // Child process
            run_child_process(args, &namespace_manager, &security_manager);
            // execvp should not return; if it does, exit with error
            std::process::exit(1);
        }
        Err(e) => {
            error!("Failed to fork: {}", e);
            return Err(NucleusError::Fork(e.to_string()));
        }
    };

    // Parent: Attach child to cgroup
    // Note: We need to attach by reading the child's PID
    let child_pid_u32 = child_pid.as_raw() as u32;
    cgroup.attach_process(child_pid_u32)?;

    // Parent: Wait for child to complete
    match waitpid(child_pid, None) {
        Ok(WaitStatus::Exited(_pid, code)) => {
            info!("Child process exited with code: {}", code);
            if code != 0 {
                return Err(NucleusError::ChildExit(code));
            }
        }
        Ok(WaitStatus::Signaled(_pid, signal, _coredump)) => {
            // Check if killed by seccomp (SIGKILL from blocked syscall)
            if signal == nix::sys::signal::Signal::SIGKILL {
                warn!("Child process killed by SIGKILL - possibly blocked syscall via seccomp");
            } else {
                warn!("Child process killed by signal: {}", signal);
            }
            return Err(NucleusError::ChildSignal(signal as i32));
        }
        Ok(status) => {
            warn!("Unexpected wait status: {:?}", status);
        }
        Err(e) => {
            error!("Failed to wait for child: {}", e);
            return Err(NucleusError::Wait(e.to_string()));
        }
    }

    // Cgroup cleanup happens automatically via Drop
    info!("Container execution completed successfully");
    Ok(())
}

/// Run a container with the given arguments (stub for non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn run_container(args: &RunArgs) -> Result<()> {
    info!("Starting container with args: {:?}", args);

    // Validate arguments
    validate_args(args)?;

    // Validate runtime option (must be 'native' or 'gvisor')
    validate_runtime(&args.runtime)?;

    // Validate gVisor availability if requested
    if args.runtime == "gvisor" && !crate::security::is_gvisor_available() {
        return Err(NucleusError::GvisorNotFound(
            "runsc not found in PATH. Install gVisor from https://gvisor.dev/docs/user_guide/install/".to_string()
        ));
    }

    // On non-Linux platforms, we cannot actually run containers
    error!("Container execution is only supported on Linux");
    Err(NucleusError::Namespace(
        "Container execution is only supported on Linux. This is a Linux-only tool by design.".to_string(),
    ))
}

/// Validate CLI arguments
fn validate_args(args: &RunArgs) -> Result<()> {
    // Check context directory exists and canonicalize
    if !args.context.exists() {
        return Err(NucleusError::ContextNotFound(args.context.clone()));
    }

    // Check context is a directory
    if !args.context.is_dir() {
        return Err(NucleusError::ContextNotDirectory(args.context.clone()));
    }

    // Canonicalize context path to prevent path traversal
    let _canonical_context = args.context.canonicalize()
        .map_err(|_| NucleusError::ContextNotFound(args.context.clone()))?;

    // Check command is provided
    if args.command.is_empty() {
        return Err(NucleusError::NoCommand);
    }

    // Validate executable name/path
    let (executable, _) = args.command_parts();
    validate_executable(&executable)?;

    // Validate hostname if provided
    if let Some(ref hostname) = args.hostname {
        validate_hostname(hostname)?;
    }

    // Validate CPU cores
    if args.cpus <= 0.0 {
        return Err(NucleusError::InvalidCpu(format!(
            "CPU cores must be positive, got: {}",
            args.cpus
        )));
    }

    debug!("Arguments validated successfully");
    Ok(())
}

/// Validate runtime option
fn validate_runtime(runtime: &str) -> Result<()> {
    match runtime {
        "native" => {
            debug!("Using native runtime");
            Ok(())
        }
        "gvisor" => {
            debug!("gVisor runtime requested");
            Ok(())
        }
        _ => Err(NucleusError::InvalidRuntime(format!(
            "Unknown runtime: {}. Supported: native, gvisor",
            runtime
        ))),
    }
}

/// Run the child process (executed after fork in the child)
#[cfg(target_os = "linux")]
fn run_child_process(args: &RunArgs, namespace_manager: &NamespaceManager, security_manager: &SecurityManager) {
    // Set hostname if specified (must be done after unshare)
    if let Err(e) = namespace_manager.set_hostname() {
        error!("Failed to set hostname: {}", e);
        std::process::exit(1);
    }

    // Get command parts
    let (executable, cmd_args) = args.command_parts();

    if executable.is_empty() {
        error!("No command specified");
        std::process::exit(1);
    }

    // Setup filesystem
    let memory_bytes = match args.memory_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to parse memory limit: {}", e);
            std::process::exit(1);
        }
    };

    // Create a unique container root path
    let container_root = std::env::temp_dir().join(format!("nucleus-{}", generate_container_id()));

    let fs = crate::filesystem::ContainerFilesystem::new(container_root.clone(), memory_bytes);

    // Setup the container filesystem
    if let Err(e) = fs.setup(args) {
        error!("Failed to setup filesystem: {}", e);
        std::process::exit(1);
    }

    // Copy executable to container
    let container_exe = match fs.copy_executable(executable) {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to copy executable: {}", e);
            std::process::exit(1);
        }
    };

    // Switch root
    if let Err(e) = fs.switch_root() {
        error!("Failed to switch root: {}", e);
        std::process::exit(1);
    }

    // Apply security settings (capabilities, seccomp)
    // This must be done after filesystem setup but before exec
    if let Err(e) = security_manager.apply() {
        error!("Failed to apply security settings: {}", e);
        std::process::exit(1);
    }

    info!("Child: Executing '{}' with args {:?}", container_exe.display(), cmd_args);

    // Convert to CString for execvp
    let exec_cstr = match std::ffi::CString::new(container_exe.to_string_lossy().into_owned()) {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid executable path: {}", e);
            std::process::exit(1);
        }
    };

    let args_cstr: Vec<std::ffi::CString> = std::iter::once(container_exe.to_string_lossy().into_owned())
        .chain(cmd_args.iter().map(|s| s.clone()))
        .filter_map(|s| std::ffi::CString::new(s).ok())
        .collect();

    // Execute the command
    match execvp(&exec_cstr, &args_cstr) {
        Ok(_) => {
            // execvp should not return on success
        }
        Err(e) => {
            error!("Failed to exec '{}': {}", container_exe.display(), e);
            std::process::exit(1);
        }
    }
}

/// Generate a unique container ID
fn generate_container_id() -> String {
    // Use first 12 characters of UUID (similar to Docker)
    // uuid.simple() returns the UUID as hex-only string (no hyphens)
    let uuid = Uuid::new_v4();
    uuid.simple()
        .to_string()
        .chars()
        .take(12)
        .collect()
}

/// Validate executable name/path for security
///
/// This validation prevents command injection by ensuring the executable:
/// - Is not empty
/// - Does not contain null bytes (handled by CString::new but check early)
/// - Does not contain shell metacharacters if it's a simple name (no path)
/// - Contains only safe characters (alphanumeric, dash, underscore, dot, forward slash)
///
/// Absolute paths are allowed but should be used with caution.
fn validate_executable(executable: &str) -> Result<()> {
    if executable.is_empty() {
        return Err(NucleusError::InvalidExecutable("Executable cannot be empty".to_string()));
    }

    // Check for null bytes (early rejection)
    if executable.contains('\0') {
        return Err(NucleusError::InvalidExecutable("Executable cannot contain null bytes".to_string()));
    }

    // Check for shell metacharacters that could be exploited
    let dangerous_chars = ['|', '&', ';', '<', '>', '`', '$', '(', ')', '{', '}', '[', ']', '!', '\n', '\r'];
    for ch in dangerous_chars {
        if executable.contains(ch) {
            return Err(NucleusError::InvalidExecutable(
                format!("Executable contains dangerous character: '{}'", ch)
            ));
        }
    }

    // For non-path executables (no '/'), validate characters are safe
    if !executable.contains('/') {
        // Simple executable name - allow alphanumeric, dash, underscore, dot
        if !executable.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
            return Err(NucleusError::InvalidExecutable(
                format!("Executable name contains invalid characters: {}", executable)
            ));
        }
    } else {
        // Path-based executable - validate it doesn't contain backslashes or other weird chars
        if executable.contains('\\') {
            return Err(NucleusError::InvalidExecutable(
                "Executable path cannot contain backslashes".to_string()
            ));
        }
        // Check for path traversal attempts
        if executable.contains("..") {
            return Err(NucleusError::InvalidExecutable(
                "Executable path cannot contain '..'".to_string()
            ));
        }
    }

    debug!("Executable validated: {}", executable);
    Ok(())
}

/// Validate hostname for security and correctness
///
/// Linux hostnames must:
/// - Be at most 64 characters
/// - Contain only alphanumeric characters and hyphens
/// - Not start or end with a hyphen
fn validate_hostname(hostname: &str) -> Result<()> {
    // Check length
    if hostname.len() > 64 {
        return Err(NucleusError::InvalidHostname(
            format!("Hostname exceeds 64 characters (got {})", hostname.len())
        ));
    }

    if hostname.is_empty() {
        return Err(NucleusError::InvalidHostname("Hostname cannot be empty".to_string()));
    }

    // Check for valid characters: alphanumeric and hyphens only
    if !hostname.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(NucleusError::InvalidHostname(
            "Hostname can only contain alphanumeric characters and hyphens".to_string()
        ));
    }

    // Check that it doesn't start or end with a hyphen
    if hostname.starts_with('-') || hostname.ends_with('-') {
        return Err(NucleusError::InvalidHostname(
            "Hostname cannot start or end with a hyphen".to_string()
        ));
    }

    debug!("Hostname validated: {}", hostname);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_container_id() {
        let id1 = generate_container_id();
        let id2 = generate_container_id();

        // IDs should be different
        assert_ne!(id1, id2);

        // ID should be 12 characters
        assert_eq!(id1.len(), 12);

        // ID should be lowercase hex
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_validate_runtime_native() {
        assert!(validate_runtime("native").is_ok());
    }

    #[test]
    fn test_validate_runtime_gvisor() {
        // gvisor is accepted but noted as not implemented
        assert!(validate_runtime("gvisor").is_ok());
    }

    #[test]
    fn test_validate_runtime_invalid() {
        assert!(validate_runtime("invalid").is_err());
        assert!(validate_runtime("").is_err());
    }

    #[test]
    fn test_validate_executable_valid() {
        assert!(validate_executable("ls").is_ok());
        assert!(validate_executable("echo").is_ok());
        assert!(validate_executable("my-app").is_ok());
        assert!(validate_executable("my_app").is_ok());
        assert!(validate_executable("app.sh").is_ok());
        assert!(validate_executable("/bin/ls").is_ok());
        assert!(validate_executable("/usr/local/bin/my-app").is_ok());
    }

    #[test]
    fn test_validate_executable_invalid() {
        assert!(validate_executable("").is_err());
        assert!(validate_executable("ls;rm -rf").is_err());
        assert!(validate_executable("ls|cat").is_err());
        assert!(validate_executable("ls`whoami`").is_err());
        assert!(validate_executable("$(whoami)").is_err());
        assert!(validate_executable("ls\0").is_err());
        assert!(validate_executable("/bin/../etc/passwd").is_err());
        assert!(validate_executable("C:\\Windows\\System32").is_err());
    }

    #[test]
    fn test_validate_hostname_valid() {
        assert!(validate_hostname("myhost").is_ok());
        assert!(validate_hostname("my-host").is_ok());
        assert!(validate_hostname("host123").is_ok());
        assert!(validate_hostname("a").is_ok());
        assert!(validate_hostname("a-b-c").is_ok());
    }

    #[test]
    fn test_validate_hostname_invalid() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-invalid").is_err());
        assert!(validate_hostname("invalid-").is_err());
        assert!(validate_hostname("invalid_host").is_err()); // underscore not allowed
        assert!(validate_hostname("invalid.host").is_err()); // dot not allowed
        assert!(validate_hostname(&"a".repeat(65)).is_err()); // too long
    }
}
