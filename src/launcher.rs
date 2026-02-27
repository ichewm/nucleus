//! Container launcher orchestration
//!
//! This module orchestrates the container creation process:
//! 1. Parse and validate CLI arguments
//! 2. Create cgroup for resource limits
//! 3. Unshare namespaces for isolation
//! 4. Fork child process
//! 5. Child: Configure namespaces, execute command
//! 6. Parent: Attach child to cgroup, wait for completion, cleanup
//!
//! Note: Full container execution is only supported on Linux.

use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[cfg(target_os = "linux")]
use nix::sys::wait::{waitpid, WaitStatus};
#[cfg(target_os = "linux")]
use nix::unistd::{execvp, fork, ForkResult};

use crate::cgroup::{Cgroup, CgroupConfig};
use crate::cli::RunArgs;
use crate::error::{NucleusError, Result};
#[cfg(target_os = "linux")]
use crate::namespace::NamespaceManager;

/// Run a container with the given arguments
#[cfg(target_os = "linux")]
pub fn run_container(args: &RunArgs) -> Result<()> {
    info!("Starting container with args: {:?}", args);

    // Validate arguments
    validate_args(args)?;

    // Parse memory limit
    let memory_bytes = args.memory_bytes()
        .map_err(NucleusError::MemoryParse)?;

    // Generate container ID
    let container_id = generate_container_id();
    info!("Container ID: {}", container_id);

    // Create cgroup
    let cgroup = Cgroup::create(&container_id)?;

    // Configure cgroup with resource limits
    let cgroup_config = CgroupConfig::new(memory_bytes, args.cpus);
    cgroup.configure(&cgroup_config)?;

    // Validate runtime
    validate_runtime(&args.runtime)?;

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
            run_child_process(args, &namespace_manager);
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
            warn!("Child process killed by signal: {}", signal);
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

    // Validate runtime
    validate_runtime(&args.runtime)?;

    // On non-Linux platforms, we cannot actually run containers
    error!("Container execution is only supported on Linux");
    Err(NucleusError::Namespace(
        "Container execution is only supported on Linux. This is a Linux-only tool by design.".to_string(),
    ))
}

/// Validate CLI arguments
fn validate_args(args: &RunArgs) -> Result<()> {
    // Check context directory exists
    if !args.context.exists() {
        return Err(NucleusError::ContextNotFound(args.context.clone()));
    }

    // Check context is a directory
    if !args.context.is_dir() {
        return Err(NucleusError::ContextNotDirectory(args.context.clone()));
    }

    // Check command is provided
    if args.command.is_empty() {
        return Err(NucleusError::NoCommand);
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
            info!("gVisor runtime requested (not yet implemented, using native)");
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
fn run_child_process(args: &RunArgs, namespace_manager: &NamespaceManager) {
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

    info!("Child: Executing '{}' with args {:?}", executable, cmd_args);

    // Convert to CString for execvp
    let exec_cstr = match std::ffi::CString::new(executable) {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid executable name: {}", e);
            std::process::exit(1);
        }
    };

    let args_cstr: Vec<std::ffi::CString> = std::iter::once(executable)
        .chain(cmd_args.iter().map(|s| s.as_str()))
        .filter_map(|s| std::ffi::CString::new(s).ok())
        .collect();

    // Execute the command
    match execvp(&exec_cstr, &args_cstr) {
        Ok(_) => {
            // execvp should not return on success
        }
        Err(e) => {
            error!("Failed to exec '{}': {}", executable, e);
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
}
