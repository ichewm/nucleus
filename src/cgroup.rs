//! cgroup v2 controller for resource management
//!
//! This module implements cgroup v2 based resource isolation and limiting.
//! Each container runs in its own cgroup with enforced memory, CPU, and process limits.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::error::{NucleusError, Result};

/// The cgroup v2 mount point
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The parent cgroup name for all nucleus containers
const NUCLEUS_CGROUP: &str = "nucleus";

/// Configuration for cgroup resource limits
#[derive(Debug, Clone)]
pub struct CgroupConfig {
    /// Hard memory limit in bytes (OOM kill if exceeded)
    pub memory_max: u64,

    /// Soft memory limit in bytes (throttle if exceeded)
    /// Set to 90% of max by default
    pub memory_high: u64,

    /// CPU quota in microseconds
    pub cpu_quota: u64,

    /// CPU period in microseconds (default: 100000 = 100ms)
    pub cpu_period: u64,

    /// Maximum number of processes (prevent fork bombs)
    pub pids_max: u64,
}

impl CgroupConfig {
    /// Create a new cgroup configuration from CLI arguments
    pub fn new(memory_bytes: u64, cpu_cores: f64) -> Self {
        // Set soft limit to 90% of hard limit
        let memory_high = (memory_bytes as f64 * 0.9) as u64;

        // Convert CPU cores to quota/period
        // period = 100ms (100000 us)
        // quota = cores * period
        let cpu_period = 100_000u64;
        let cpu_quota = (cpu_cores * cpu_period as f64) as u64;

        // Default PID limit
        let pids_max = 1024u64;

        Self {
            memory_max: memory_bytes,
            memory_high,
            cpu_quota,
            cpu_period,
            pids_max,
        }
    }
}

/// Represents a cgroup for a nucleus container
pub struct Cgroup {
    /// Path to the cgroup directory
    path: PathBuf,

    /// Container ID (used in cgroup name)
    container_id: String,
}

impl Cgroup {
    /// Create a new cgroup for a container
    ///
    /// # Arguments
    /// * `container_id` - Unique identifier for the container
    ///
    /// # Returns
    /// The created Cgroup instance
    pub fn create(container_id: &str) -> Result<Self> {
        let nucleus_root = Path::new(CGROUP_ROOT).join(NUCLEUS_CGROUP);
        let cgroup_path = nucleus_root.join(format!("nucleus-{}", container_id));

        info!("Creating cgroup at {:?}", cgroup_path);

        // Ensure the parent nucleus cgroup exists
        if !nucleus_root.exists() {
            fs::create_dir_all(&nucleus_root).map_err(|_| {
                NucleusError::CgroupCreate(nucleus_root.clone())
            })?;
            debug!("Created parent cgroup directory: {:?}", nucleus_root);
        }

        // Create the container-specific cgroup
        fs::create_dir_all(&cgroup_path).map_err(|_| {
            NucleusError::CgroupCreate(cgroup_path.clone())
        })?;

        debug!("Created cgroup directory: {:?}", cgroup_path);

        Ok(Self {
            path: cgroup_path,
            container_id: container_id.to_string(),
        })
    }

    /// Configure the cgroup with resource limits
    pub fn configure(&self, config: &CgroupConfig) -> Result<()> {
        info!(
            "Configuring cgroup with memory={}MB, CPU quota={}/{}us",
            config.memory_max / (1024 * 1024),
            config.cpu_quota,
            config.cpu_period
        );

        // Set memory limits
        self.write_file("memory.max", &config.memory_max.to_string())?;
        self.write_file("memory.high", &config.memory_high.to_string())?;

        // Disable swap
        self.write_file("memory.swap.max", "0")?;

        // Set CPU limits
        self.write_file(
            "cpu.max",
            &format!("{} {}", config.cpu_quota, config.cpu_period),
        )?;

        // Set PID limits
        self.write_file("pids.max", &config.pids_max.to_string())?;

        debug!("Cgroup configured successfully");
        Ok(())
    }

    /// Attach a process to this cgroup
    ///
    /// # Arguments
    /// * `pid` - Process ID to attach
    pub fn attach_process(&self, pid: u32) -> Result<()> {
        info!("Attaching process {} to cgroup", pid);
        self.write_file("cgroup.procs", &pid.to_string())?;
        Ok(())
    }

    /// Clean up the cgroup
    ///
    /// This will kill any remaining processes and remove the cgroup directory
    pub fn cleanup(&self) -> Result<()> {
        info!("Cleaning up cgroup at {:?}", self.path);

        // Read remaining processes
        let procs = self.read_file("cgroup.procs")?;

        if !procs.trim().is_empty() {
            warn!("Killing remaining processes in cgroup");

            // Kill remaining processes
            for pid_str in procs.lines() {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    // Try to kill the process
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    debug!("Sent SIGKILL to process {}", pid);
                }
            }

            // Give processes time to terminate
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Remove cgroup directory
        if self.path.exists() {
            fs::remove_dir(&self.path).map_err(|e| {
                NucleusError::CgroupCleanup(format!("Failed to remove {:?}: {}", self.path, e))
            })?;
        }

        debug!("Cgroup cleaned up successfully");
        Ok(())
    }

    /// Get the path to this cgroup
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write a value to a cgroup control file
    fn write_file(&self, name: &str, value: &str) -> Result<()> {
        let path = self.path.join(name);
        debug!("Writing {:?} to {:?}", value, path);

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|_| NucleusError::CgroupWrite(path.clone()))?;

        file.write_all(value.as_bytes())
            .map_err(|_| NucleusError::CgroupWrite(path.clone()))?;

        Ok(())
    }

    /// Read a value from a cgroup control file
    fn read_file(&self, name: &str) -> Result<String> {
        let path = self.path.join(name);

        let mut file = fs::File::open(&path)
            .map_err(|_| NucleusError::CgroupRead(path.clone()))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|_| NucleusError::CgroupRead(path.clone()))?;

        Ok(contents)
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Attempt cleanup on drop, but don't panic if it fails
        if let Err(e) = self.cleanup() {
            warn!("Failed to cleanup cgroup on drop: {}", e);
        }
    }
}

/// Check if cgroup v2 is available on this system
pub fn is_cgroup_v2_available() -> bool {
    Path::new(CGROUP_ROOT).join("cgroup.controllers").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_config_new() {
        let config = CgroupConfig::new(512 * 1024 * 1024, 2.0);

        assert_eq!(config.memory_max, 512 * 1024 * 1024);
        assert_eq!(config.memory_high, (512.0 * 1024.0 * 1024.0 * 0.9) as u64);
        assert_eq!(config.cpu_period, 100_000);
        assert_eq!(config.cpu_quota, 200_000); // 2.0 * 100000
        assert_eq!(config.pids_max, 1024);
    }

    #[test]
    fn test_cgroup_config_fractional_cpu() {
        let config = CgroupConfig::new(1024 * 1024 * 1024, 0.5);

        assert_eq!(config.cpu_quota, 50_000); // 0.5 * 100000
    }

    #[test]
    fn test_cgroup_config_large_memory() {
        let config = CgroupConfig::new(4 * 1024 * 1024 * 1024, 4.0);

        assert_eq!(config.memory_max, 4 * 1024 * 1024 * 1024);
        assert_eq!(config.cpu_quota, 400_000); // 4.0 * 100000
    }

    // Note: Actual cgroup creation tests require root and cgroup v2 support
    // These are integration tests that would be run in a proper test environment
}
