//! Error handling using thiserror

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias for nucleus operations
pub type Result<T> = std::result::Result<T, NucleusError>;

/// All possible errors in nucleus
#[derive(Error, Debug)]
pub enum NucleusError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse memory size: {0}")]
    MemoryParse(String),

    #[error("Context directory does not exist: {0}")]
    ContextNotFound(PathBuf),

    #[error("Context directory is not a directory: {0}")]
    ContextNotDirectory(PathBuf),

    #[error("Invalid CPU value: {0}")]
    InvalidCpu(String),

    #[error("Cgroup error: {0}")]
    Cgroup(String),

    #[error("Namespace error: {0}")]
    Namespace(String),

    #[error("Failed to create cgroup directory: {0}")]
    CgroupCreate(PathBuf),

    #[error("Failed to write cgroup control file: {0}")]
    CgroupWrite(PathBuf),

    #[error("Failed to read cgroup control file: {0}")]
    CgroupRead(PathBuf),

    #[error("Failed to attach process to cgroup: {0}")]
    CgroupAttach(String),

    #[error("Failed to cleanup cgroup: {0}")]
    CgroupCleanup(String),

    #[error("Failed to unshare namespaces: {0}")]
    Unshare(String),

    #[error("Failed to set hostname: {0}")]
    SetHostname(String),

    #[error("Failed to fork process: {0}")]
    Fork(String),

    #[error("Failed to wait for child process: {0}")]
    Wait(String),

    #[error("Child process exited with code: {0}")]
    ChildExit(i32),

    #[error("Child process was killed by signal: {0}")]
    ChildSignal(i32),

    #[error("Command not specified")]
    NoCommand,

    #[error("Invalid runtime: {0}")]
    InvalidRuntime(String),

    #[error("Invalid executable name: {0}")]
    InvalidExecutable(String),

    #[error("Invalid container ID: {0}")]
    InvalidContainerId(String),

    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),

    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),

    // Filesystem errors
    #[error("Failed to mount filesystem: {0}")]
    FilesystemMount(String),

    #[error("Failed to create filesystem layout: {0}")]
    FilesystemLayout(String),

    #[error("Failed to create device node: {0}")]
    DeviceNode(String),

    #[error("Failed to copy context from {0}: {1}")]
    ContextCopy(PathBuf, String),

    #[error("Failed to pivot_root: {0}")]
    PivotRoot(String),

    #[error("Failed to chroot: {0}")]
    Chroot(String),

    // Security errors
    #[error("Failed to drop capabilities: {0}")]
    CapabilityDrop(String),

    #[error("Failed to set capabilities: {0}")]
    CapabilitySet(String),

    #[error("Failed to apply seccomp filter: {0}")]
    SeccompApply(String),

    #[error("Failed to compile seccomp filter: {0}")]
    SeccompCompile(String),

    #[error("gVisor runtime (runsc) not found: {0}")]
    GvisorNotFound(String),

    #[error("Failed to execute with gVisor: {0}")]
    GvisorExecute(String),
}
