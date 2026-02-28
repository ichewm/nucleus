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
}
