//! Security enforcement layer for nucleus containers
//!
//! This module implements defense-in-depth security:
//! - Capability dropping using `caps` crate
//! - Seccomp filtering using `seccompiler` crate
//! - gVisor integration for syscall interception
//!
//! Note: Most operations are only supported on Linux.

use std::path::PathBuf;

use tracing::{debug, info, warn};

use crate::error::{NucleusError, Result};

// Linux-only imports for seccompiler
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

/// Security profile for a container
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    /// Whether to drop all capabilities (default: true)
    pub drop_all_capabilities: bool,

    /// Specific capabilities to retain (if drop_all is false)
    pub retain_capabilities: Vec<String>,

    /// Whether to apply seccomp filter (default: true)
    pub apply_seccomp: bool,

    /// Custom blocked syscalls (added to default blocked list)
    pub extra_blocked_syscalls: Vec<String>,

    /// Custom allowed syscalls (added to default allowed list)
    pub extra_allowed_syscalls: Vec<String>,
}

impl Default for SecurityProfile {
    fn default() -> Self {
        Self {
            drop_all_capabilities: true,
            retain_capabilities: Vec::new(),
            apply_seccomp: true,
            extra_blocked_syscalls: Vec::new(),
            extra_allowed_syscalls: Vec::new(),
        }
    }
}

impl SecurityProfile {
    /// Create a new security profile with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive profile (no seccomp, minimal capability dropping)
    pub fn permissive() -> Self {
        Self {
            drop_all_capabilities: false,
            retain_capabilities: vec!["CAP_NET_BIND_SERVICE".to_string()],
            apply_seccomp: false,
            extra_blocked_syscalls: Vec::new(),
            extra_allowed_syscalls: Vec::new(),
        }
    }

    /// Create a strict profile (maximum security)
    pub fn strict() -> Self {
        Self {
            drop_all_capabilities: true,
            retain_capabilities: Vec::new(),
            apply_seccomp: true,
            extra_blocked_syscalls: vec![
                "ptrace".to_string(),
                "kexec_load".to_string(),
                "kexec_file_load".to_string(),
                "add_key".to_string(),
                "request_key".to_string(),
                "keyctl".to_string(),
                "bpf".to_string(),
                "perf_event_open".to_string(),
                "userfaultfd".to_string(),
                "io_uring_setup".to_string(),
                "io_uring_enter".to_string(),
                "io_uring_register".to_string(),
                "memfd_create".to_string(),
                "mlock".to_string(),
                "mlockall".to_string(),
            ],
            extra_allowed_syscalls: Vec::new(),
        }
    }
}

/// Drop all capabilities from the bounding set and effective set
///
/// This prevents the process from gaining any privileged capabilities,
/// even if it tries to exec a setuid binary.
#[cfg(target_os = "linux")]
pub fn drop_all_capabilities() -> Result<()> {
    use caps::CapsHashSet;
    use caps::securebits::set_keepcaps;
    use caps::CapSet;

    info!("Dropping all capabilities");

    // Clear the bounding set first (prevents gaining caps via exec)
    caps::set(None, CapSet::Bounding, CapsHashSet::empty())
        .map_err(|e| NucleusError::CapabilityDrop(format!("Failed to clear bounding set: {}", e)))?;

    // Don't keep capabilities across setuid
    set_keepcaps(false)
        .map_err(|e| NucleusError::CapabilityDrop(format!("Failed to set keepcaps: {}", e)))?;

    // Clear all capability sets
    for capset in [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
    ] {
        caps::set(None, capset, CapsHashSet::empty())
            .map_err(|e| {
                NucleusError::CapabilityDrop(format!("Failed to clear {:?} set: {}", capset, e))
            })?;
    }

    debug!("All capabilities dropped successfully");
    Ok(())
}

/// Drop all capabilities (stub for non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn drop_all_capabilities() -> Result<()> {
    warn!("Capability dropping is only supported on Linux");
    Ok(())
}

/// Set specific capabilities for the process
///
/// # Arguments
/// * `capabilities` - List of capability names to set (e.g., "CAP_NET_BIND_SERVICE")
#[cfg(target_os = "linux")]
pub fn set_capabilities(capabilities: &[String]) -> Result<()> {
    use caps::{CapSet, Capability, CapsHashSet};

    if capabilities.is_empty() {
        return drop_all_capabilities();
    }

    info!("Setting capabilities: {:?}", capabilities);

    let mut caps = CapsHashSet::new();
    for cap_str in capabilities {
        let cap = cap_str.parse::<Capability>().map_err(|e| {
            NucleusError::CapabilitySet(format!("Invalid capability '{}': {}", cap_str, e))
        })?;
        caps.insert(cap);
    }

    // Set the capabilities in all relevant sets
    for capset in [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
    ] {
        caps::set(None, capset, caps.clone())
            .map_err(|e| NucleusError::CapabilitySet(format!("Failed to set {:?}: {}", capset, e)))?;
    }

    debug!("Capabilities set successfully");
    Ok(())
}

/// Set specific capabilities (stub for non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn set_capabilities(_capabilities: &[String]) -> Result<()> {
    warn!("Capability setting is only supported on Linux");
    Ok(())
}

/// Get the default list of blocked syscalls
///
/// These are syscalls that are commonly used for privilege escalation
/// or container escapes.
fn get_default_blocked_syscalls() -> Vec<&'static str> {
    vec![
        // Process tracing/debugging
        "ptrace",
        // Kernel operations
        "kexec_load",
        "kexec_file_load",
        "init_module",
        "finit_module",
        "delete_module",
        // Kernel keyring
        "add_key",
        "request_key",
        "keyctl",
        // eBPF and performance
        "bpf",
        "perf_event_open",
        // User fault handling
        "userfaultfd",
        // Async I/O (potential escape vector)
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        // File descriptor replacement
        "dup3",
        // Namespace/module operations (for rootless)
        // Note: We allow these for now as we may need them
        // "unshare",
        // "setns",
        // Clock management
        "clock_settime",
        "clock_adjtime",
        // System configuration
        "sysctl",
        "acct",
        "swapon",
        "swapoff",
        // Reboot
        "reboot",
        // Hardware control
        "iopl",
        "ioperm",
    ]
}

/// Build a seccomp filter for the container
///
/// Creates a BPF filter that:
/// - Allows all syscalls by default (within the container)
/// - Blocks specific dangerous syscalls
#[cfg(target_os = "linux")]
pub fn build_seccomp_filter(profile: &SecurityProfile) -> Result<seccompiler::BpfProgram> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArg, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    info!("Building seccomp filter");

    // Detect architecture
    let arch = TargetArch::get_current()
        .map_err(|e| NucleusError::SeccompCompile(format!("Failed to detect architecture: {}", e)))?;

    // Build the map of blocked syscalls with their rules
    let mut rules: BTreeMap<String, Vec<SeccompRule>> = BTreeMap::new();

    // Get default blocked syscalls
    let mut blocked = get_default_blocked_syscalls();

    // Add extra blocked syscalls from profile
    for syscall in &profile.extra_blocked_syscalls {
        if !blocked.contains(&syscall.as_str()) {
            blocked.push(syscall.as_str());
        }
    }

    // Add each blocked syscall with a KILL action rule
    for syscall in blocked {
        // Empty rule vector means "block on any condition"
        rules.insert(syscall.to_string(), Vec::new());
    }

    // Create the filter
    // Default action: ALLOW (we use blocklist approach)
    // Specific rules: KILL for dangerous syscalls
    let filter = SeccompFilter::new(
        rules.into_iter().collect(),
        SeccompAction::Allow,  // Default: allow syscalls
        SeccompAction::Kill,   // Matched rules: kill process
        arch,
    )
    .map_err(|e| NucleusError::SeccompCompile(format!("Failed to create filter: {}", e)))?;

    // Compile to BPF
    let bpf = filter
        .try_into()
        .map_err(|e| NucleusError::SeccompCompile(format!("Failed to compile BPF: {}", e)))?;

    debug!("Seccomp filter compiled successfully");
    Ok(bpf)
}

/// Build seccomp filter (stub for non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn build_seccomp_filter(_profile: &SecurityProfile) -> Result<Vec<u8>> {
    warn!("Seccomp is only supported on Linux");
    Ok(Vec::new())
}

/// Apply the seccomp filter to the current process
///
/// This must be called after forking and before exec.
/// Once applied, the filter cannot be removed.
#[cfg(target_os = "linux")]
pub fn apply_seccomp_filter(bpf: &seccompiler::BpfProgram) -> Result<()> {
    use seccompiler::apply_filter;

    info!("Applying seccomp filter ({} bytes)", bpf.len());

    apply_filter(bpf)
        .map_err(|e| NucleusError::SeccompApply(format!("Failed to apply filter: {}", e)))?;

    debug!("Seccomp filter applied successfully");
    Ok(())
}

/// Apply seccomp filter (stub for non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp_filter(_bpf: &[u8]) -> Result<()> {
    warn!("Seccomp is only supported on Linux");
    Ok(())
}

/// Check if gVisor runtime (runsc) is available
pub fn is_gvisor_available() -> bool {
    which::which("runsc").is_ok()
}

/// Find the path to the gVisor runtime (runsc)
pub fn find_gvisor_runtime() -> Result<PathBuf> {
    which::which("runsc").map_err(|_| {
        NucleusError::GvisorNotFound(
            "runsc not found in PATH. Install gVisor from https://gvisor.dev/docs/user_guide/install/"
                .to_string(),
        )
    })
}

/// Security manager for container isolation
pub struct SecurityManager {
    /// Security profile to apply
    profile: SecurityProfile,

    /// Whether gVisor runtime is requested
    use_gvisor: bool,

    /// Compiled seccomp filter (cached)
    #[cfg(target_os = "linux")]
    seccomp_filter: Option<seccompiler::BpfProgram>,
}

impl SecurityManager {
    /// Create a new security manager with the given profile
    pub fn new(profile: SecurityProfile, use_gvisor: bool) -> Self {
        Self {
            profile,
            use_gvisor,
            #[cfg(target_os = "linux")]
            seccomp_filter: None,
        }
    }

    /// Create a security manager with default profile
    pub fn default_profile(use_gvisor: bool) -> Self {
        Self::new(SecurityProfile::default(), use_gvisor)
    }

    /// Create a security manager with strict profile
    pub fn strict_profile(use_gvisor: bool) -> Self {
        Self::new(SecurityProfile::strict(), use_gvisor)
    }

    /// Prepare security settings (compile seccomp filter, etc.)
    ///
    /// This should be called before forking.
    #[cfg(target_os = "linux")]
    pub fn prepare(&mut self) -> Result<()> {
        if self.profile.apply_seccomp {
            let filter = build_seccomp_filter(&self.profile)?;
            self.seccomp_filter = Some(filter);
        }
        Ok(())
    }

    /// Prepare security settings (stub for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn prepare(&mut self) -> Result<()> {
        Ok(())
    }

    /// Apply all security settings in the child process
    ///
    /// This should be called in the child after fork, before exec.
    /// Order matters: capabilities first, then seccomp.
    pub fn apply(&self) -> Result<()> {
        // Drop capabilities first
        if self.profile.drop_all_capabilities {
            drop_all_capabilities()?;
        } else if !self.profile.retain_capabilities.is_empty() {
            set_capabilities(&self.profile.retain_capabilities)?;
        }

        // Apply seccomp filter
        if self.profile.apply_seccomp {
            #[cfg(target_os = "linux")]
            if let Some(ref filter) = self.seccomp_filter {
                apply_seccomp_filter(filter)?;
            }
        }

        info!("Security settings applied successfully");
        Ok(())
    }

    /// Check if gVisor should be used
    pub fn should_use_gvisor(&self) -> bool {
        self.use_gvisor
    }

    /// Check if gVisor is available
    pub fn is_gvisor_available(&self) -> bool {
        is_gvisor_available()
    }

    /// Get the gVisor runtime path
    pub fn gvisor_runtime_path(&self) -> Result<PathBuf> {
        find_gvisor_runtime()
    }

    /// Get the security profile
    pub fn profile(&self) -> &SecurityProfile {
        &self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_profile_default() {
        let profile = SecurityProfile::default();

        assert!(profile.drop_all_capabilities);
        assert!(profile.apply_seccomp);
        assert!(profile.retain_capabilities.is_empty());
        assert!(profile.extra_blocked_syscalls.is_empty());
    }

    #[test]
    fn test_security_profile_permissive() {
        let profile = SecurityProfile::permissive();

        assert!(!profile.drop_all_capabilities);
        assert!(!profile.apply_seccomp);
        assert!(!profile.retain_capabilities.is_empty());
        assert!(profile.retain_capabilities.contains(&"CAP_NET_BIND_SERVICE".to_string()));
    }

    #[test]
    fn test_security_profile_strict() {
        let profile = SecurityProfile::strict();

        assert!(profile.drop_all_capabilities);
        assert!(profile.apply_seccomp);
        assert!(!profile.extra_blocked_syscalls.is_empty());
        assert!(profile.extra_blocked_syscalls.contains(&"ptrace".to_string()));
        assert!(profile.extra_blocked_syscalls.contains(&"bpf".to_string()));
    }

    #[test]
    fn test_default_blocked_syscalls() {
        let blocked = get_default_blocked_syscalls();

        // Verify critical syscalls are blocked
        assert!(blocked.contains(&"ptrace"));
        assert!(blocked.contains(&"kexec_load"));
        assert!(blocked.contains(&"add_key"));
        assert!(blocked.contains(&"bpf"));
        assert!(blocked.contains(&"perf_event_open"));
        assert!(blocked.contains(&"userfaultfd"));
    }

    #[test]
    fn test_security_manager_default() {
        let manager = SecurityManager::default_profile(false);

        assert!(!manager.should_use_gvisor());
        assert!(manager.profile().apply_seccomp);
        assert!(manager.profile().drop_all_capabilities);
    }

    #[test]
    fn test_security_manager_gvisor() {
        let manager = SecurityManager::default_profile(true);

        assert!(manager.should_use_gvisor());
    }

    #[test]
    fn test_security_manager_strict() {
        let manager = SecurityManager::strict_profile(false);

        assert!(manager.profile().apply_seccomp);
        assert!(manager.profile().drop_all_capabilities);
        assert!(!manager.profile().extra_blocked_syscalls.is_empty());
    }

    // Test that capability string parsing works
    #[test]
    #[cfg(target_os = "linux")]
    fn test_capability_parsing() {
        use caps::Capability;

        // Valid capabilities should parse
        assert!("CAP_NET_BIND_SERVICE".parse::<Capability>().is_ok());
        assert!("CAP_SYS_ADMIN".parse::<Capability>().is_ok());
        assert!("CAP_KILL".parse::<Capability>().is_ok());

        // Invalid capabilities should fail
        assert!("CAP_FAKE_CAPABILITY".parse::<Capability>().is_err());
        assert!("NOT_A_CAP".parse::<Capability>().is_err());
    }

    // Note: Tests that actually apply capabilities or seccomp require root
    // and would affect the test process, so we only test the logic,
    // not the actual application.
}
