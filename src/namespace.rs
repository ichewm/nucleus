//! Namespace manager using nix crate
//!
//! This module handles Linux namespace isolation using all 6 namespace types:
//! - PID: Process isolation (container sees PID 1)
//! - Mount: Filesystem isolation
//! - Network: Network stack isolation (no network by default)
//! - UTS: Hostname/domain isolation
//! - IPC: Inter-process communication isolation
//! - User: UID/GID mapping (for rootless containers)
//!
//! Note: This module is only available on Linux.

#[cfg(target_os = "linux")]
use nix::sched::{CloneFlags, unshare};
#[cfg(target_os = "linux")]
use nix::unistd::sethostname;
use tracing::{debug, info};

use crate::error::{NucleusError, Result};

/// Bitflags for namespace types
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub struct NamespaceFlags(CloneFlags);

#[cfg(target_os = "linux")]
impl NamespaceFlags {
    /// Create flags for all standard namespaces (no user namespace)
    pub fn all() -> Self {
        Self(
            CloneFlags::CLONE_NEWPID  // PID namespace
                | CloneFlags::CLONE_NEWNS   // Mount namespace
                | CloneFlags::CLONE_NEWNET  // Network namespace
                | CloneFlags::CLONE_NEWUTS  // UTS namespace (hostname)
                | CloneFlags::CLONE_NEWIPC, // IPC namespace
        )
    }

    /// Create flags for all namespaces including user namespace (for rootless)
    pub fn all_with_user() -> Self {
        Self(
            CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWNET
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWUSER, // User namespace
        )
    }

    /// Get the underlying CloneFlags
    pub fn flags(&self) -> CloneFlags {
        self.0
    }
}

#[cfg(target_os = "linux")]
impl Default for NamespaceFlags {
    fn default() -> Self {
        Self::all()
    }
}

/// Namespace manager for container isolation
pub struct NamespaceManager {
    /// Configured hostname for the container
    hostname: Option<String>,

    /// Namespace flags to use (Linux only)
    #[cfg(target_os = "linux")]
    flags: NamespaceFlags,
}

impl NamespaceManager {
    /// Create a new namespace manager
    pub fn new(hostname: Option<String>) -> Self {
        Self {
            hostname,
            #[cfg(target_os = "linux")]
            flags: NamespaceFlags::all(),
        }
    }

    /// Create a new namespace manager with custom flags
    #[cfg(target_os = "linux")]
    pub fn with_flags(hostname: Option<String>, flags: NamespaceFlags) -> Self {
        Self { hostname, flags }
    }

    /// Unshare all configured namespaces
    ///
    /// This must be called before forking for PID namespace to work correctly.
    /// For PID namespace, the actual isolation happens when the first child is created.
    #[cfg(target_os = "linux")]
    pub fn unshare_namespaces(&self) -> Result<()> {
        info!("Unsharing namespaces: {:?}", self.flags);

        unshare(self.flags.flags()).map_err(|e| {
            NucleusError::Unshare(format!("Failed to unshare namespaces: {}", e))
        })?;

        debug!("Namespaces unshared successfully");
        Ok(())
    }

    /// Unshare all configured namespaces (stub for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn unshare_namespaces(&self) -> Result<()> {
        info!("Namespace operations not supported on this platform");
        Err(NucleusError::Namespace(
            "Namespaces are only supported on Linux".to_string(),
        ))
    }

    /// Set the hostname in the new UTS namespace
    ///
    /// This must be called after unshare_namespaces() and inside the new namespace
    #[cfg(target_os = "linux")]
    pub fn set_hostname(&self) -> Result<()> {
        if let Some(ref hostname) = self.hostname {
            info!("Setting container hostname to: {}", hostname);

            sethostname(hostname).map_err(|e| {
                NucleusError::SetHostname(format!("Failed to set hostname: {}", e))
            })?;

            debug!("Hostname set successfully");
        }
        Ok(())
    }

    /// Set the hostname (stub for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn set_hostname(&self) -> Result<()> {
        if self.hostname.is_some() {
            debug!("Hostname setting not supported on this platform");
        }
        Ok(())
    }

    /// Get the namespace flags
    #[cfg(target_os = "linux")]
    pub fn flags(&self) -> NamespaceFlags {
        self.flags
    }

    /// Check if user namespace is enabled
    #[cfg(target_os = "linux")]
    pub fn has_user_namespace(&self) -> bool {
        self.flags.flags().contains(CloneFlags::CLONE_NEWUSER)
    }

    /// Check if user namespace is enabled (stub for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn has_user_namespace(&self) -> bool {
        false
    }
}

/// Generate a description of namespace flags for logging
#[cfg(target_os = "linux")]
pub fn describe_flags(flags: NamespaceFlags) -> String {
    let cf = flags.flags();
    let mut parts = Vec::new();

    if cf.contains(CloneFlags::CLONE_NEWPID) {
        parts.push("PID");
    }
    if cf.contains(CloneFlags::CLONE_NEWNS) {
        parts.push("Mount");
    }
    if cf.contains(CloneFlags::CLONE_NEWNET) {
        parts.push("Network");
    }
    if cf.contains(CloneFlags::CLONE_NEWUTS) {
        parts.push("UTS");
    }
    if cf.contains(CloneFlags::CLONE_NEWIPC) {
        parts.push("IPC");
    }
    if cf.contains(CloneFlags::CLONE_NEWUSER) {
        parts.push("User");
    }

    parts.join(", ")
}

/// Generate a description of namespace flags for logging (stub for non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn describe_flags(_flags: ()) -> String {
    "Namespaces not supported on this platform".to_string()
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_flags_all() {
        let flags = NamespaceFlags::all();
        let cf = flags.flags();

        assert!(cf.contains(CloneFlags::CLONE_NEWPID));
        assert!(cf.contains(CloneFlags::CLONE_NEWNS));
        assert!(cf.contains(CloneFlags::CLONE_NEWNET));
        assert!(cf.contains(CloneFlags::CLONE_NEWUTS));
        assert!(cf.contains(CloneFlags::CLONE_NEWIPC));
        assert!(!cf.contains(CloneFlags::CLONE_NEWUSER));
    }

    #[test]
    fn test_namespace_flags_all_with_user() {
        let flags = NamespaceFlags::all_with_user();
        let cf = flags.flags();

        assert!(cf.contains(CloneFlags::CLONE_NEWPID));
        assert!(cf.contains(CloneFlags::CLONE_NEWNS));
        assert!(cf.contains(CloneFlags::CLONE_NEWNET));
        assert!(cf.contains(CloneFlags::CLONE_NEWUTS));
        assert!(cf.contains(CloneFlags::CLONE_NEWIPC));
        assert!(cf.contains(CloneFlags::CLONE_NEWUSER));
    }

    #[test]
    fn test_namespace_manager_new() {
        let manager = NamespaceManager::new(Some("test-container".to_string()));

        assert_eq!(manager.hostname, Some("test-container".to_string()));
        assert!(!manager.has_user_namespace());
    }

    #[test]
    fn test_describe_flags_all() {
        let desc = describe_flags(NamespaceFlags::all());
        assert!(desc.contains("PID"));
        assert!(desc.contains("Mount"));
        assert!(desc.contains("Network"));
        assert!(desc.contains("UTS"));
        assert!(desc.contains("IPC"));
        assert!(!desc.contains("User"));
    }

    #[test]
    fn test_describe_flags_with_user() {
        let desc = describe_flags(NamespaceFlags::all_with_user());
        assert!(desc.contains("User"));
    }
}
