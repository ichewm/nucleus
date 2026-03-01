//! cgroup v2 controller for resource management
//!
//! This module implements cgroup v2 based resource isolation and limiting.
//! Each container runs in its own cgroup with enforced memory, CPU, I/O, and process limits.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::error::{NucleusError, Result};

/// The cgroup v2 mount point
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The parent cgroup name for all nucleus containers
const NUCLEUS_CGROUP: &str = "nucleus";

/// Per-device I/O limits for cgroup v2 io.max controller
///
/// The device identifier is in "major:minor" format (e.g., "8:0" for /dev/sda).
/// Limits are optional - only specified limits will be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoDeviceLimit {
    /// Major:minor device number (e.g., "8:0" for /dev/sda)
    pub device: String,

    /// Read IOPS limit (operations per second)
    pub riops: Option<u64>,

    /// Write IOPS limit (operations per second)
    pub wiops: Option<u64>,

    /// Read bandwidth limit (bytes per second)
    pub rbps: Option<u64>,

    /// Write bandwidth limit (bytes per second)
    pub wbps: Option<u64>,
}

impl IoDeviceLimit {
    /// Create a new I/O device limit with the specified device and limits
    pub fn new(
        device: String,
        riops: Option<u64>,
        wiops: Option<u64>,
        rbps: Option<u64>,
        wbps: Option<u64>,
    ) -> Self {
        Self {
            device,
            riops,
            wiops,
            rbps,
            wbps,
        }
    }

    /// Format the limit for writing to io.max
    /// Format: "major:minor riops=N wiops=N rbps=N wbps=N"
    /// Only specified limits are included in the output
    pub fn to_io_max_format(&self) -> String {
        let mut parts = vec![self.device.clone()];

        if let Some(riops) = self.riops {
            parts.push(format!("riops={}", riops));
        }
        if let Some(wiops) = self.wiops {
            parts.push(format!("wiops={}", wiops));
        }
        if let Some(rbps) = self.rbps {
            parts.push(format!("rbps={}", rbps));
        }
        if let Some(wbps) = self.wbps {
            parts.push(format!("wbps={}", wbps));
        }

        parts.join(" ")
    }
}

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

    /// I/O limits for devices (optional)
    pub io_limits: Vec<IoDeviceLimit>,
}

impl CgroupConfig {
    /// Create a new cgroup configuration from CLI arguments
    pub fn new(memory_bytes: u64, cpu_cores: f64) -> Self {
        Self::with_io_limits(memory_bytes, cpu_cores, Vec::new())
    }

    /// Create a new cgroup configuration with I/O limits
    pub fn with_io_limits(memory_bytes: u64, cpu_cores: f64, io_limits: Vec<IoDeviceLimit>) -> Self {
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
            io_limits,
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
        // Validate container_id to prevent path traversal attacks
        // Only allow alphanumeric characters and hyphens
        if container_id.is_empty() {
            return Err(NucleusError::CgroupCreate(PathBuf::from("container_id cannot be empty")));
        }
        if !container_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(NucleusError::CgroupCreate(PathBuf::from(
                format!("Invalid container ID: must contain only alphanumeric characters, hyphens, or underscores")
            )));
        }
        if container_id.contains("..") {
            return Err(NucleusError::CgroupCreate(PathBuf::from(
                "Invalid container ID: cannot contain '..'"
            )));
        }

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

        // Set I/O limits if specified
        for io_limit in &config.io_limits {
            self.set_io_limit(io_limit)?;
        }

        debug!("Cgroup configured successfully");
        Ok(())
    }

    /// Set I/O limits for a device using the io.max controller
    ///
    /// # Arguments
    /// * `limit` - The I/O device limit to apply
    ///
    /// # Format
    /// The io.max file format is: "major:minor riops=N wiops=N rbps=N wbps=N"
    /// Only specified limits are written; "max" is used for unlimited.
    pub fn set_io_limit(&self, limit: &IoDeviceLimit) -> Result<()> {
        let io_max_value = limit.to_io_max_format();
        info!("Setting I/O limit: {}", io_max_value);
        self.write_file("io.max", &io_max_value)?;
        debug!("I/O limit applied for device {}", limit.device);
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

/// Device information parsed from /proc/partitions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Major device number
    pub major: u32,
    /// Minor device number
    pub minor: u32,
    /// Device name (e.g., "sda", "nvme0n1")
    pub name: String,
}

impl DeviceInfo {
    /// Get the device identifier in "major:minor" format for io.max
    pub fn to_dev_id(&self) -> String {
        format!("{}:{}", self.major, self.minor)
    }
}

/// Parse /proc/partitions to get device information
///
/// Format of /proc/partitions:
/// major minor  #blocks  name
///
/// Example:
///    8        0  500107608 sda
///    8        1  500106816 sda1
///  259        0  500107608 nvme0n1
pub fn parse_proc_partitions() -> Result<Vec<DeviceInfo>> {
    let path = Path::new("/proc/partitions");

    if !path.exists() {
        return Err(NucleusError::DeviceParse(
            "/proc/partitions not found".to_string()
        ));
    }

    let file = fs::File::open(path)
        .map_err(|e| NucleusError::DeviceParse(format!("Failed to open /proc/partitions: {}", e)))?;

    let reader = BufReader::new(file);
    let mut devices = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            NucleusError::DeviceParse(format!("Failed to read line: {}", e))
        })?;

        // Skip header lines (first two lines)
        if line_num < 2 {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                devices.push(DeviceInfo {
                    major,
                    minor,
                    name: parts[3].to_string(),
                });
            }
        }
    }

    Ok(devices)
}

/// Detect the root device by finding the device mounted at /
///
/// This function reads /proc/mounts to find the root filesystem device,
/// then looks up its major:minor numbers in /proc/partitions.
pub fn detect_root_device() -> Result<DeviceInfo> {
    // Read /proc/mounts to find the root device
    let mounts_path = Path::new("/proc/mounts");
    if !mounts_path.exists() {
        return Err(NucleusError::RootDeviceDetect(
            "/proc/mounts not found".to_string()
        ));
    }

    let mounts_content = fs::read_to_string(mounts_path)
        .map_err(|e| NucleusError::RootDeviceDetect(
            format!("Failed to read /proc/mounts: {}", e)
        ))?;

    // Find the root mount entry
    // Format: device mountpoint fstype options dump pass
    let root_device_name = mounts_content
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some("/"))
        .and_then(|line| line.split_whitespace().next())
        .map(|s| s.to_string());

    let root_device_name = root_device_name.ok_or_else(|| {
        NucleusError::RootDeviceDetect("Could not find root device in /proc/mounts".to_string())
    })?;

    debug!("Root device name from /proc/mounts: {}", root_device_name);

    // Handle special device names
    let device_basename = if root_device_name.starts_with("/dev/") {
        // Extract just the device name (e.g., "sda1" from "/dev/sda1")
        root_device_name.trim_start_matches("/dev/").to_string()
    } else if root_device_name.starts_with("UUID=") || root_device_name.starts_with("LABEL=") {
        // For UUID/LABEL mounts, we need to resolve to actual device
        // This is more complex; for now, try to find it via /dev/disk/by-uuid or similar
        // As a fallback, we'll read /dev/root symlink if it exists
        return resolve_root_device_from_dev_root();
    } else {
        root_device_name.clone()
    };

    // Parse /proc/partitions to find the device info
    let devices = parse_proc_partitions()?;

    // First try exact match
    if let Some(device) = devices.iter().find(|d| d.name == device_basename) {
        info!("Detected root device: {} ({})", device.name, device.to_dev_id());
        return Ok(device.clone());
    }

    // If the device is a partition (e.g., sda1), find the parent device (e.g., sda)
    // by stripping trailing digits
    let parent_name = device_basename.trim_end_matches(|c: char| c.is_ascii_digit());
    if let Some(device) = devices.iter().find(|d| d.name == parent_name && d.minor == 0) {
        info!(
            "Detected root device parent: {} ({}) from partition {}",
            device.name, device.to_dev_id(), device_basename
        );
        return Ok(device.clone());
    }

    Err(NucleusError::RootDeviceDetect(format!(
        "Could not find device info for '{}' in /proc/partitions",
        device_basename
    )))
}

/// Resolve root device by reading /dev/root symlink
fn resolve_root_device_from_dev_root() -> Result<DeviceInfo> {
    let dev_root = Path::new("/dev/root");

    if !dev_root.exists() {
        return Err(NucleusError::RootDeviceDetect(
            "/dev/root does not exist and root is mounted by UUID/LABEL".to_string()
        ));
    }

    // Read the symlink target
    let target = fs::read_link(dev_root)
        .map_err(|e| NucleusError::RootDeviceDetect(
            format!("Failed to read /dev/root symlink: {}", e)
        ))?;

    let device_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| NucleusError::RootDeviceDetect(
            "Could not extract device name from /dev/root target".to_string()
        ))?;

    debug!("Root device from /dev/root symlink: {}", device_name);

    // Parse /proc/partitions to find the device info
    let devices = parse_proc_partitions()?;

    if let Some(device) = devices.iter().find(|d| d.name == device_name) {
        info!("Detected root device: {} ({})", device.name, device.to_dev_id());
        return Ok(device.clone());
    }

    Err(NucleusError::RootDeviceDetect(format!(
        "Could not find device info for '{}' in /proc/partitions",
        device_name
    )))
}

/// Parse I/O limit specification string
///
/// Format: `<device>:<riops>:<wiops>:<rbps>:<wbps>`
/// - device: Either "auto" for root device auto-detection, or "major:minor" format
/// - riops: Read IOPS limit (use "0" or "max" for unlimited)
/// - wiops: Write IOPS limit
/// - rbps: Read bytes per second (supports K/M/G suffixes)
/// - wbps: Write bytes per second (supports K/M/G suffixes)
///
/// Examples:
/// - `auto:1000:1000:10M:10M` - Auto-detect root device, limit to 1000 IOPS and 10MB/s
/// - `8:0:5000:5000:100M:100M` - Specific device 8:0 with limits
/// - `auto:0:0:50M:50M` - Auto-detect, no IOPS limit, 50MB/s bandwidth limit
pub fn parse_io_limit_spec(spec: &str) -> Result<IoDeviceLimit> {
    let parts: Vec<&str> = spec.split(':').collect();

    if parts.len() != 5 {
        return Err(NucleusError::InvalidIoLimit(format!(
            "Invalid I/O limit format. Expected: device:riops:wiops:rbps:wbps, got: {}",
            spec
        )));
    }

    // Determine device
    let device = if parts[0].eq_ignore_ascii_case("auto") {
        // Auto-detect root device
        let root_device = detect_root_device()?;
        root_device.to_dev_id()
    } else {
        // Validate device format (major:minor)
        let dev_parts: Vec<&str> = parts[0].split(':').collect();
        if dev_parts.len() != 2 {
            return Err(NucleusError::InvalidIoLimit(format!(
                "Invalid device format. Expected 'major:minor' or 'auto', got: {}",
                parts[0]
            )));
        }
        if dev_parts[0].parse::<u32>().is_err() || dev_parts[1].parse::<u32>().is_err() {
            return Err(NucleusError::InvalidIoLimit(format!(
                "Invalid device numbers. Expected numeric major:minor, got: {}",
                parts[0]
            )));
        }
        parts[0].to_string()
    };

    // Parse limits
    let riops = parse_io_limit_value(parts[1], "riops")?;
    let wiops = parse_io_limit_value(parts[2], "wiops")?;
    let rbps = parse_io_bandwidth_value(parts[3], "rbps")?;
    let wbps = parse_io_bandwidth_value(parts[4], "wbps")?;

    Ok(IoDeviceLimit::new(device, riops, wiops, rbps, wbps))
}

/// Parse an I/O limit value (IOPS or raw number)
fn parse_io_limit_value(value: &str, field: &str) -> Result<Option<u64>> {
    let value = value.trim();

    if value.eq_ignore_ascii_case("max") || value == "0" || value.is_empty() {
        return Ok(None); // No limit
    }

    value.parse::<u64>()
        .map(Some)
        .map_err(|_| NucleusError::InvalidIoLimit(format!(
            "Invalid {} value: {}",
            field, value
        )))
}

/// Parse an I/O bandwidth value with optional K/M/G suffix
fn parse_io_bandwidth_value(value: &str, field: &str) -> Result<Option<u64>> {
    let value = value.trim();

    if value.eq_ignore_ascii_case("max") || value == "0" || value.is_empty() {
        return Ok(None); // No limit
    }

    let value_upper = value.to_uppercase();

    let (num_str, multiplier) = if value_upper.ends_with("GB") {
        (&value_upper[..value_upper.len() - 2], 1024u64 * 1024 * 1024)
    } else if value_upper.ends_with("G") {
        (&value_upper[..value_upper.len() - 1], 1024u64 * 1024 * 1024)
    } else if value_upper.ends_with("MB") {
        (&value_upper[..value_upper.len() - 2], 1024u64 * 1024)
    } else if value_upper.ends_with("M") {
        (&value_upper[..value_upper.len() - 1], 1024u64 * 1024)
    } else if value_upper.ends_with("KB") {
        (&value_upper[..value_upper.len() - 2], 1024u64)
    } else if value_upper.ends_with("K") {
        (&value_upper[..value_upper.len() - 1], 1024u64)
    } else if value_upper.ends_with("B") {
        (&value_upper[..value_upper.len() - 1], 1u64)
    } else {
        (value_upper.as_str(), 1u64)
    };

    let num: u64 = num_str.parse()
        .map_err(|_| NucleusError::InvalidIoLimit(format!(
            "Invalid {} value: {}",
            field, value
        )))?;

    Ok(Some(num * multiplier))
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

    // Unit tests for container ID validation (doesn't require cgroup v2)
    #[test]
    fn test_container_id_validation_valid() {
        // These should pass validation (though cgroup creation may fail without root)
        fn validate_id(id: &str) -> bool {
            !id.is_empty()
                && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && !id.contains("..")
        }

        assert!(validate_id("abc123"));
        assert!(validate_id("my-container"));
        assert!(validate_id("container_123"));
        assert!(validate_id("a"));
    }

    #[test]
    fn test_container_id_validation_invalid() {
        fn validate_id(id: &str) -> bool {
            !id.is_empty()
                && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && !id.contains("..")
        }

        assert!(!validate_id("")); // empty
        assert!(!validate_id("../etc")); // path traversal
        assert!(!validate_id("container..name")); // double dots
        assert!(!validate_id("container/name")); // slash
        assert!(!validate_id("container name")); // space
        assert!(!validate_id("container\nname")); // newline
    }

    // =========================================================================
    // I/O limit tests
    // =========================================================================

    #[test]
    fn test_io_device_limit_format() {
        // Test with all limits specified
        let limit = IoDeviceLimit::new(
            "8:0".to_string(),
            Some(1000),
            Some(2000),
            Some(10 * 1024 * 1024),
            Some(20 * 1024 * 1024),
        );
        assert_eq!(limit.to_io_max_format(), "8:0 riops=1000 wiops=2000 rbps=10485760 wbps=20971520");
    }

    #[test]
    fn test_io_device_limit_partial() {
        // Test with only some limits specified
        let limit = IoDeviceLimit::new(
            "259:0".to_string(),
            None,
            Some(500),
            Some(5 * 1024 * 1024),
            None,
        );
        assert_eq!(limit.to_io_max_format(), "259:0 wiops=500 rbps=5242880");
    }

    #[test]
    fn test_io_device_limit_no_limits() {
        // Test with no limits (device only)
        let limit = IoDeviceLimit::new(
            "8:16".to_string(),
            None,
            None,
            None,
            None,
        );
        assert_eq!(limit.to_io_max_format(), "8:16");
    }

    #[test]
    fn test_cgroup_config_with_io_limits() {
        let io_limits = vec![
            IoDeviceLimit::new("8:0".to_string(), Some(1000), Some(1000), None, None),
            IoDeviceLimit::new("259:0".to_string(), None, None, Some(10 * 1024 * 1024), Some(10 * 1024 * 1024)),
        ];

        let config = CgroupConfig::with_io_limits(512 * 1024 * 1024, 2.0, io_limits);

        assert_eq!(config.memory_max, 512 * 1024 * 1024);
        assert_eq!(config.cpu_quota, 200_000);
        assert_eq!(config.io_limits.len(), 2);
        assert_eq!(config.io_limits[0].device, "8:0");
        assert_eq!(config.io_limits[0].riops, Some(1000));
        assert_eq!(config.io_limits[1].device, "259:0");
        assert_eq!(config.io_limits[1].rbps, Some(10 * 1024 * 1024));
    }

    #[test]
    fn test_parse_io_bandwidth_bytes() {
        assert_eq!(parse_io_bandwidth_value("1024", "test").unwrap(), Some(1024));
        assert_eq!(parse_io_bandwidth_value("1024B", "test").unwrap(), Some(1024));
    }

    #[test]
    fn test_parse_io_bandwidth_kilobytes() {
        assert_eq!(parse_io_bandwidth_value("1K", "test").unwrap(), Some(1024));
        assert_eq!(parse_io_bandwidth_value("2KB", "test").unwrap(), Some(2048));
        assert_eq!(parse_io_bandwidth_value("10k", "test").unwrap(), Some(10 * 1024));
    }

    #[test]
    fn test_parse_io_bandwidth_megabytes() {
        assert_eq!(parse_io_bandwidth_value("1M", "test").unwrap(), Some(1024 * 1024));
        assert_eq!(parse_io_bandwidth_value("10MB", "test").unwrap(), Some(10 * 1024 * 1024));
        assert_eq!(parse_io_bandwidth_value("100m", "test").unwrap(), Some(100 * 1024 * 1024));
    }

    #[test]
    fn test_parse_io_bandwidth_gigabytes() {
        assert_eq!(parse_io_bandwidth_value("1G", "test").unwrap(), Some(1024 * 1024 * 1024));
        assert_eq!(parse_io_bandwidth_value("2GB", "test").unwrap(), Some(2 * 1024 * 1024 * 1024));
    }

    #[test]
    fn test_parse_io_bandwidth_unlimited() {
        assert_eq!(parse_io_bandwidth_value("max", "test").unwrap(), None);
        assert_eq!(parse_io_bandwidth_value("0", "test").unwrap(), None);
        assert_eq!(parse_io_bandwidth_value("", "test").unwrap(), None);
    }

    #[test]
    fn test_parse_io_bandwidth_invalid() {
        assert!(parse_io_bandwidth_value("abc", "test").is_err());
    }

    #[test]
    fn test_parse_io_limit_value_valid() {
        assert_eq!(parse_io_limit_value("1000", "test").unwrap(), Some(1000));
        assert_eq!(parse_io_limit_value("50000", "test").unwrap(), Some(50000));
    }

    #[test]
    fn test_parse_io_limit_value_unlimited() {
        assert_eq!(parse_io_limit_value("max", "test").unwrap(), None);
        assert_eq!(parse_io_limit_value("0", "test").unwrap(), None);
        assert_eq!(parse_io_limit_value("", "test").unwrap(), None);
    }

    #[test]
    fn test_parse_io_limit_value_invalid() {
        assert!(parse_io_limit_value("abc", "test").is_err());
        assert!(parse_io_limit_value("-1", "test").is_err());
    }

    #[test]
    fn test_device_info_to_dev_id() {
        let device = DeviceInfo {
            major: 8,
            minor: 0,
            name: "sda".to_string(),
        };
        assert_eq!(device.to_dev_id(), "8:0");

        let device2 = DeviceInfo {
            major: 259,
            minor: 1,
            name: "nvme0n1p1".to_string(),
        };
        assert_eq!(device2.to_dev_id(), "259:1");
    }

    // Note: Actual cgroup creation tests require root and cgroup v2 support
    // These are integration tests that would be run in a proper test environment
}
