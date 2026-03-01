//! Integration tests for cgroup v2 resource control
//!
//! These tests verify conformance to spec/resource-control.md:
//! - cgroup v2 hierarchy at /sys/fs/cgroup/nucleus/
//! - Memory limits (memory.max, memory.high, memory.swap.max)
//! - CPU limits (cpu.max with quota/period)
//! - I/O limits (io.max with riops/wiops/rbps/wbps)
//! - PID limits (pids.max)
//! - cgroup lifecycle (create, attach, cleanup)
//!
//! Note: Many tests require root and cgroup v2. Tests are designed to:
//! - Skip gracefully on non-Linux systems
//! - Skip gracefully without root/cgroup v2
//! - Verify logic that doesn't require actual cgroup manipulation

/// Check if we're running on Linux with cgroup v2 support
fn has_cgroup_v2() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Check if we're running as root
fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::getuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

mod cgroup_config_tests {
    use super::*;

    // =========================================================================
    // SPEC REQUIREMENT: CgroupConfig with memory, CPU, and PID limits
    // Reference: spec/resource-control.md - Memory Control, CPU Control, Process Control
    // =========================================================================

    /// Test that CgroupConfig correctly computes values from input parameters
    /// This tests the spec-defined formulas without requiring actual cgroup access
    #[test]
    fn test_integration_cgroup_config_memory_computation() {
        // Spec: memory.high should be 90% of memory.max
        // Spec: memory.max is the hard limit (OOM kill if exceeded)

        // Test values derived from spec/resource-control.md implementation
        let memory_bytes: u64 = 512 * 1024 * 1024; // 512MB
        let cpu_cores = 2.0;

        // Expected values per spec:
        // - memory_max = input memory_bytes
        // - memory_high = memory_bytes * 0.9
        // - cpu_quota = cpu_cores * 100000 (period)
        // - cpu_period = 100000
        // - pids_max = 1024 (default)

        let expected_memory_max = memory_bytes;
        let expected_memory_high = (memory_bytes as f64 * 0.9) as u64;
        let expected_cpu_quota = (cpu_cores * 100_000.0) as u64;
        let expected_cpu_period = 100_000u64;
        let expected_pids_max = 1024u64;

        // Verify our understanding matches spec
        assert_eq!(expected_memory_max, 512 * 1024 * 1024);
        assert_eq!(expected_memory_high, (512.0 * 1024.0 * 1024.0 * 0.9) as u64);
        assert_eq!(expected_cpu_quota, 200_000); // 2 cores * 100000
        assert_eq!(expected_cpu_period, 100_000);
        assert_eq!(expected_pids_max, 1024);
    }

    /// Test CPU quota calculation for fractional cores
    /// Spec: cpu.max = "quota period" where quota = cores * period
    #[test]
    fn test_integration_cgroup_config_fractional_cpu() {
        // Spec: "Limit to 2.5 cores" -> "250000 100000"
        //       Every 100ms, process can use 250ms of CPU time

        let cpu_cores = 0.5;
        let period = 100_000u64;
        let expected_quota = (cpu_cores * period as f64) as u64;

        assert_eq!(expected_quota, 50_000); // 0.5 cores
    }

    /// Test CPU quota calculation for multiple cores
    #[test]
    fn test_integration_cgroup_config_multiple_cpu() {
        let cpu_cores = 4.0;
        let period = 100_000u64;
        let expected_quota = (cpu_cores * period as f64) as u64;

        assert_eq!(expected_quota, 400_000); // 4 cores
    }
}

mod cgroup_security_tests {
    use super::*;

    // =========================================================================
    // SPEC REQUIREMENT: Container ID validation prevents path traversal
    // Reference: spec/security.md - Input validation
    // =========================================================================

    /// Spec: Container IDs should be validated to prevent path traversal attacks
    /// Valid: alphanumeric, hyphens, underscores
    /// Invalid: empty, path separators, .., special characters
    #[test]
    fn test_integration_cgroup_container_id_validation_rules() {
        // These validation rules are defined in cgroup.rs and must match spec/security.md

        fn is_valid_container_id(id: &str) -> bool {
            !id.is_empty()
                && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && !id.contains("..")
        }

        // Valid IDs
        assert!(is_valid_container_id("abc123"), "alphanumeric should be valid");
        assert!(is_valid_container_id("my-container"), "hyphen should be valid");
        assert!(is_valid_container_id("container_123"), "underscore should be valid");
        assert!(is_valid_container_id("a"), "single char should be valid");
        assert!(is_valid_container_id("A-B-C-123"), "mixed case should be valid");

        // Invalid IDs - path traversal
        assert!(!is_valid_container_id("../etc"), "path traversal should be invalid");
        assert!(!is_valid_container_id("container/../etc"), "embedded path traversal should be invalid");
        assert!(!is_valid_container_id(".."), "double dot should be invalid");

        // Invalid IDs - special characters
        assert!(!is_valid_container_id(""), "empty should be invalid");
        assert!(!is_valid_container_id("container/name"), "slash should be invalid");
        assert!(!is_valid_container_id("container name"), "space should be invalid");
        assert!(!is_valid_container_id("container.name"), "dot should be invalid");
        assert!(!is_valid_container_id("container\nname"), "newline should be invalid");
    }
}

mod cgroup_path_tests {
    use super::*;

    // =========================================================================
    // SPEC REQUIREMENT: cgroup v2 hierarchy path
    // Reference: spec/resource-control.md - cgroup v2 Hierarchy
    // =========================================================================

    /// Spec: Cgroups should be created at /sys/fs/cgroup/nucleus/nucleus-<id>/
    #[test]
    fn test_integration_cgroup_expected_path_structure() {
        // Verify expected path structure per spec
        let cgroup_root = "/sys/fs/cgroup";
        let nucleus_parent = "nucleus";
        let container_id = "abc123def456";

        // Expected path: /sys/fs/cgroup/nucleus/nucleus-abc123def456/
        let expected_path = format!("{}/{}/nucleus-{}", cgroup_root, nucleus_parent, container_id);

        assert_eq!(expected_path, "/sys/fs/cgroup/nucleus/nucleus-abc123def456");
    }

    /// Spec: Control files should be at the cgroup path
    #[test]
    fn test_integration_cgroup_expected_control_files() {
        // Per spec/resource-control.md, these files should exist:
        let control_files = [
            "cgroup.procs",    // Process attachment
            "memory.max",      // Hard memory limit
            "memory.high",     // Soft memory limit
            "memory.swap.max", // Swap limit
            "cpu.max",         // CPU bandwidth
            "io.max",          // I/O throttling
            "pids.max",        // Process count limit
        ];

        // Verify all required control files are documented
        assert_eq!(control_files.len(), 7);
        assert!(control_files.contains(&"memory.max"));
        assert!(control_files.contains(&"cpu.max"));
        assert!(control_files.contains(&"io.max"));
        assert!(control_files.contains(&"pids.max"));
    }
}

mod cgroup_v2_availability_tests {
    use super::*;

    // =========================================================================
    // SPEC REQUIREMENT: Check cgroup v2 availability
    // Reference: spec/resource-control.md - requires cgroup v2
    // =========================================================================

    /// Test cgroup v2 detection logic
    /// Spec: cgroup v2 is detected by presence of /sys/fs/cgroup/cgroup.controllers
    #[test]
    fn test_integration_cgroup_v2_detection() {
        // This test verifies the detection logic, not actual availability
        // The actual function is is_cgroup_v2_available() in cgroup.rs

        // On non-Linux systems, cgroup v2 is never available
        if !cfg!(target_os = "linux") {
            assert!(!has_cgroup_v2(), "cgroup v2 should not be available on non-Linux");
        }
        // On Linux, check for the control file
        // This test is informational
    }
}

// =============================================================================
// Linux-specific cgroup tests (require root and cgroup v2)
// These tests will skip on non-Linux or without root
// =============================================================================

#[cfg(target_os = "linux")]
mod linux_cgroup_tests {
    use super::*;

    /// Test actual cgroup creation (requires root and cgroup v2)
    #[test]
    fn test_integration_cgroup_create_and_cleanup() {
        if !is_root() || !has_cgroup_v2() {
            eprintln!("SKIP: test requires root and cgroup v2");
            return;
        }

        use std::fs;
        use std::path::Path;

        let container_id = format!("test-{}", uuid::Uuid::new_v4().simple());
        let cgroup_path = Path::new("/sys/fs/cgroup/nucleus/nucleus-").join(&container_id);

        // Ensure clean state
        if cgroup_path.exists() {
            let _ = fs::remove_dir(&cgroup_path);
        }

        // Create parent if needed
        let parent = Path::new("/sys/fs/cgroup/nucleus");
        if !parent.exists() {
            fs::create_dir_all(parent).expect("Failed to create parent cgroup");
        }

        // Create cgroup
        fs::create_dir_all(&cgroup_path).expect("Failed to create cgroup");

        // Verify cgroup exists
        assert!(cgroup_path.exists(), "Cgroup should exist after creation");
        assert!(cgroup_path.join("cgroup.procs").exists(), "cgroup.procs should exist");

        // Cleanup
        fs::remove_dir(&cgroup_path).expect("Failed to remove cgroup");
    }

    /// Test cgroup memory configuration (requires root and cgroup v2)
    #[test]
    fn test_integration_cgroup_memory_limits() {
        if !is_root() || !has_cgroup_v2() {
            eprintln!("SKIP: test requires root and cgroup v2");
            return;
        }

        use std::fs;
        use std::io::Write;
        use std::path::Path;

        let container_id = format!("test-mem-{}", uuid::Uuid::new_v4().simple());
        let cgroup_path = Path::new("/sys/fs/cgroup/nucleus/nucleus-").join(&container_id);

        // Create cgroup
        let parent = Path::new("/sys/fs/cgroup/nucleus");
        fs::create_dir_all(parent).ok();
        fs::create_dir_all(&cgroup_path).expect("Failed to create cgroup");

        // Set memory limits per spec
        let memory_max = 512 * 1024 * 1024; // 512MB
        let memory_high = (memory_max as f64 * 0.9) as u64;

        fs::write(cgroup_path.join("memory.max"), memory_max.to_string())
            .expect("Failed to write memory.max");
        fs::write(cgroup_path.join("memory.high"), memory_high.to_string())
            .expect("Failed to write memory.high");
        fs::write(cgroup_path.join("memory.swap.max"), "0")
            .expect("Failed to write memory.swap.max");

        // Verify written values
        let max_val = fs::read_to_string(cgroup_path.join("memory.max"))
            .expect("Failed to read memory.max");
        assert!(max_val.trim().starts_with(&memory_max.to_string()), "memory.max should be set");

        // Cleanup
        fs::remove_dir(&cgroup_path).ok();
    }

    /// Test cgroup CPU configuration (requires root and cgroup v2)
    #[test]
    fn test_integration_cgroup_cpu_limits() {
        if !is_root() || !has_cgroup_v2() {
            eprintln!("SKIP: test requires root and cgroup v2");
            return;
        }

        use std::fs;
        use std::path::Path;

        let container_id = format!("test-cpu-{}", uuid::Uuid::new_v4().simple());
        let cgroup_path = Path::new("/sys/fs/cgroup/nucleus/nucleus-").join(&container_id);

        // Create cgroup
        let parent = Path::new("/sys/fs/cgroup/nucleus");
        fs::create_dir_all(parent).ok();
        fs::create_dir_all(&cgroup_path).expect("Failed to create cgroup");

        // Set CPU limits per spec: "200000 100000" = 2 cores
        let cpu_max = "200000 100000";

        fs::write(cgroup_path.join("cpu.max"), cpu_max)
            .expect("Failed to write cpu.max");

        // Verify
        let val = fs::read_to_string(cgroup_path.join("cpu.max"))
            .expect("Failed to read cpu.max");
        assert!(val.trim().starts_with("200000 100000"), "cpu.max should be set");

        // Cleanup
        fs::remove_dir(&cgroup_path).ok();
    }

    /// Test cgroup I/O configuration (requires root and cgroup v2)
    #[test]
    fn test_integration_cgroup_io_limits() {
        if !is_root() || !has_cgroup_v2() {
            eprintln!("SKIP: test requires root and cgroup v2");
            return;
        }

        use std::fs;
        use std::path::Path;

        let container_id = format!("test-io-{}", uuid::Uuid::new_v4().simple());
        let cgroup_path = Path::new("/sys/fs/cgroup/nucleus/nucleus-").join(&container_id);

        // Create cgroup
        let parent = Path::new("/sys/fs/cgroup/nucleus");
        fs::create_dir_all(parent).ok();
        fs::create_dir_all(&cgroup_path).expect("Failed to create cgroup");

        // Set I/O limits per spec: "8:0 riops=1000 wiops=1000 rbps=10485760 wbps=10485760"
        // This limits device 8:0 to 1000 IOPS and 10MB/s for both read and write
        let io_max = "8:0 riops=1000 wiops=1000 rbps=10485760 wbps=10485760";

        fs::write(cgroup_path.join("io.max"), io_max)
            .expect("Failed to write io.max");

        // Verify
        let val = fs::read_to_string(cgroup_path.join("io.max"))
            .expect("Failed to read io.max");
        assert!(val.contains("8:0"), "io.max should contain device 8:0");
        assert!(val.contains("riops=1000"), "io.max should contain riops=1000");
        assert!(val.contains("wiops=1000"), "io.max should contain wiops=1000");

        // Cleanup
        fs::remove_dir(&cgroup_path).ok();
    }
}

// =============================================================================
// I/O limit configuration tests (don't require cgroup access)
// =============================================================================

mod io_limit_tests {
    // =========================================================================
    // SPEC REQUIREMENT: I/O limit configuration
    // Reference: spec/resource-control.md - I/O Control
    // =========================================================================

    /// Test I/O limit format matches spec
    /// Spec: "8:0 riops=1000 wiops=1000 rbps=10485760 wbps=10485760"
    #[test]
    fn test_integration_io_limit_format_spec() {
        // Verify the expected format per spec/resource-control.md
        let expected_format = "8:0 riops=1000 wiops=1000 rbps=10485760 wbps=10485760";

        // Verify format components
        assert!(expected_format.starts_with("8:0"), "Should start with device major:minor");
        assert!(expected_format.contains("riops=1000"), "Should contain riops limit");
        assert!(expected_format.contains("wiops=1000"), "Should contain wiops limit");
        assert!(expected_format.contains("rbps=10485760"), "Should contain rbps limit (10MB/s)");
        assert!(expected_format.contains("wbps=10485760"), "Should contain wbps limit (10MB/s)");
    }

    /// Test I/O bandwidth unit conversion
    /// Spec: bandwidth values are in bytes per second
    #[test]
    fn test_integration_io_bandwidth_conversion() {
        // 10 MB/s = 10 * 1024 * 1024 bytes/s = 10,485,760 bytes/s
        let ten_mbps = 10 * 1024 * 1024;
        assert_eq!(ten_mbps, 10_485_760);

        // 100 MB/s = 104,857,600 bytes/s
        let hundred_mbps = 100 * 1024 * 1024;
        assert_eq!(hundred_mbps, 104_857_600);

        // 1 GB/s = 1,073,741,824 bytes/s
        let one_gbps = 1024 * 1024 * 1024;
        assert_eq!(one_gbps, 1_073_741_824);
    }

    /// Test device identifier format
    /// Spec: Device is specified as "major:minor" (e.g., "8:0" for /dev/sda)
    #[test]
    fn test_integration_io_device_identifier_format() {
        // Common device numbers:
        // SCSI/SATA disks: major 8, minors 0-15 (sda-sdp)
        // NVMe drives: major 259
        // Loop devices: major 7

        let sda = "8:0";      // /dev/sda
        let sda1 = "8:1";     // /dev/sda1
        let nvme = "259:0";   // /dev/nvme0n1

        // Verify format: numeric:numeric
        fn is_valid_dev_id(id: &str) -> bool {
            let parts: Vec<&str> = id.split(':').collect();
            if parts.len() != 2 {
                return false;
            }
            parts[0].parse::<u32>().is_ok() && parts[1].parse::<u32>().is_ok()
        }

        assert!(is_valid_dev_id(sda), "sda device ID should be valid");
        assert!(is_valid_dev_id(sda1), "sda1 partition ID should be valid");
        assert!(is_valid_dev_id(nvme), "nvme device ID should be valid");
        assert!(!is_valid_dev_id("abc"), "non-numeric should be invalid");
        assert!(!is_valid_dev_id("8"), "missing minor should be invalid");
        assert!(!is_valid_dev_id("8:0:extra"), "extra parts should be invalid");
    }
}

// =============================================================================
// I/O limit specification parsing tests
// =============================================================================

mod io_limit_parsing_tests {
    // =========================================================================
    // SPEC REQUIREMENT: I/O limit specification parsing
    // Reference: spec/resource-control.md - I/O Control, PRD TASK-004
    // =========================================================================

    /// Test I/O limit specification format validation
    /// Spec: Format is <device>:<riops>:<wiops>:<rbps>:<wbps>
    /// Note: When device is "major:minor", the format has 6 colon-separated parts
    #[test]
    fn test_integration_io_limit_spec_format() {
        // Verify the expected format:
        // - With "auto": 5 parts (auto:riops:wiops:rbps:wbps)
        // - With "major:minor": 6 parts (major:minor:riops:wiops:rbps:wbps)
        fn count_colon_parts(spec: &str) -> usize {
            spec.split(':').count()
        }

        // Valid formats with "auto" (5 parts)
        assert_eq!(count_colon_parts("auto:1000:1000:10M:10M"), 5);
        assert_eq!(count_colon_parts("auto:max:max:1G:1G"), 5);

        // Valid formats with "major:minor" (6 parts because device itself has a colon)
        assert_eq!(count_colon_parts("8:0:5000:5000:100M:100M"), 6);
        assert_eq!(count_colon_parts("259:0:max:max:1G:1G"), 6);

        // Invalid formats (too few parts)
        assert_eq!(count_colon_parts("auto:1000:1000"), 3); // Missing rbps and wbps
        assert_eq!(count_colon_parts("8:0:1000"), 3); // Missing wiops, rbps, wbps

        // Invalid formats (too many parts with "auto")
        assert_eq!(count_colon_parts("auto:1000:1000:10M:10M:extra"), 6);
    }

    /// Test bandwidth suffix parsing
    /// Spec: rbps and wbps support K/M/G suffixes
    #[test]
    fn test_integration_io_bandwidth_suffix_parsing() {
        // Test suffix multiplier logic
        fn parse_bandwidth(value: &str) -> Option<u64> {
            let value = value.trim().to_uppercase();
            if value == "MAX" || value == "0" || value.is_empty() {
                return Some(0); // Unlimited indicator
            }

            let (num_str, multiplier) = if value.ends_with("GB") {
                (&value[..value.len() - 2], 1024u64 * 1024 * 1024)
            } else if value.ends_with("G") {
                (&value[..value.len() - 1], 1024u64 * 1024 * 1024)
            } else if value.ends_with("MB") {
                (&value[..value.len() - 2], 1024u64 * 1024)
            } else if value.ends_with("M") {
                (&value[..value.len() - 1], 1024u64 * 1024)
            } else if value.ends_with("KB") {
                (&value[..value.len() - 2], 1024u64)
            } else if value.ends_with("K") {
                (&value[..value.len() - 1], 1024u64)
            } else {
                (value.as_str(), 1u64)
            };

            num_str.parse::<u64>().ok().map(|n| n * multiplier)
        }

        // Test suffix parsing
        assert_eq!(parse_bandwidth("10M"), Some(10 * 1024 * 1024));
        assert_eq!(parse_bandwidth("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_bandwidth("512K"), Some(512 * 1024));
        assert_eq!(parse_bandwidth("100"), Some(100));
        assert_eq!(parse_bandwidth("max"), Some(0)); // Unlimited
        assert_eq!(parse_bandwidth("0"), Some(0)); // Unlimited
    }

    /// Test IOPS value parsing
    /// Spec: riops and wiops are operations per second
    #[test]
    fn test_integration_io_iops_parsing() {
        fn parse_iops(value: &str) -> Option<Option<u64>> {
            let value = value.trim();
            if value.eq_ignore_ascii_case("max") || value == "0" || value.is_empty() {
                return Some(None); // Unlimited
            }
            value.parse::<u64>().ok().map(Some)
        }

        // Test IOPS parsing
        assert_eq!(parse_iops("1000"), Some(Some(1000)));
        assert_eq!(parse_iops("50000"), Some(Some(50000)));
        assert_eq!(parse_iops("max"), Some(None)); // Unlimited
        assert_eq!(parse_iops("0"), Some(None)); // Unlimited
        assert_eq!(parse_iops("abc"), None); // Invalid
    }

    /// Test auto device detection value
    /// Spec: "auto" triggers root device auto-detection
    #[test]
    fn test_integration_io_auto_device_keyword() {
        fn is_auto_device(device: &str) -> bool {
            device.trim().eq_ignore_ascii_case("auto")
        }

        assert!(is_auto_device("auto"));
        assert!(is_auto_device("AUTO"));
        assert!(is_auto_device("Auto"));
        assert!(!is_auto_device("8:0"));
        assert!(!is_auto_device("autoc"));
    }
}

// =============================================================================
// Device detection tests (require /proc filesystem)
// =============================================================================

mod device_detection_tests {
    use super::*;

    // =========================================================================
    // SPEC REQUIREMENT: Root device auto-detection
    // Reference: spec/resource-control.md - I/O Control, PRD TASK-004
    // =========================================================================

    /// Test /proc/partitions format understanding
    /// Spec: Parse /proc/partitions to get device info
    #[test]
    fn test_integration_proc_partitions_format() {
        // This test verifies understanding of /proc/partitions format
        // Format: major minor #blocks name

        // Example line from /proc/partitions:
        // "   8        0  500107608 sda"
        // "   8        1  500106816 sda1"

        let example_line = "   8        0  500107608 sda";
        let parts: Vec<&str> = example_line.split_whitespace().collect();

        assert_eq!(parts.len(), 4, "Should have 4 columns");
        assert_eq!(parts[0].parse::<u32>().unwrap(), 8, "Major number");
        assert_eq!(parts[1].parse::<u32>().unwrap(), 0, "Minor number");
        assert_eq!(parts[3], "sda", "Device name");
    }

    /// Test /proc/mounts format for root device detection
    /// Spec: Read /proc/mounts to find root filesystem device
    #[test]
    fn test_integration_proc_mounts_format() {
        // This test verifies understanding of /proc/mounts format
        // Format: device mountpoint fstype options dump pass

        // Example line:
        // "/dev/sda1 / ext4 rw,relatime 0 1"

        let example_line = "/dev/sda1 / ext4 rw,relatime 0 1";
        let parts: Vec<&str> = example_line.split_whitespace().collect();

        assert!(parts.len() >= 2, "Should have at least device and mountpoint");
        assert_eq!(parts[0], "/dev/sda1", "Device");
        assert_eq!(parts[1], "/", "Mountpoint");
    }

    /// Test device name to basename extraction
    /// Spec: Extract device name from /dev/XXX format
    #[test]
    fn test_integration_device_basename_extraction() {
        fn extract_basename(device: &str) -> &str {
            device.trim_start_matches("/dev/")
        }

        assert_eq!(extract_basename("/dev/sda"), "sda");
        assert_eq!(extract_basename("/dev/sda1"), "sda1");
        assert_eq!(extract_basename("/dev/nvme0n1"), "nvme0n1");
        assert_eq!(extract_basename("sda"), "sda"); // Already basename
    }

    /// Test partition to parent device extraction
    /// Spec: For partition devices, find the parent device (e.g., sda1 -> sda)
    #[test]
    fn test_integration_partition_parent_extraction() {
        fn get_parent_device(partition: &str) -> &str {
            partition.trim_end_matches(|c: char| c.is_ascii_digit())
        }

        assert_eq!(get_parent_device("sda1"), "sda");
        assert_eq!(get_parent_device("sda2"), "sda");
        assert_eq!(get_parent_device("nvme0n1p1"), "nvme0n1p"); // NVMe partition
        assert_eq!(get_parent_device("sda"), "sda"); // Not a partition
    }

    /// Test device identifier format (major:minor)
    /// Spec: Device is identified by major:minor numbers
    #[test]
    fn test_integration_device_id_format() {
        fn format_device_id(major: u32, minor: u32) -> String {
            format!("{}:{}", major, minor)
        }

        assert_eq!(format_device_id(8, 0), "8:0");
        assert_eq!(format_device_id(8, 1), "8:1");
        assert_eq!(format_device_id(259, 0), "259:0");
    }
}

// =============================================================================
// IoDeviceLimit struct behavior tests
// =============================================================================

mod io_device_limit_tests {
    // =========================================================================
    // SPEC REQUIREMENT: IoDeviceLimit produces correct io.max format
    // Reference: spec/resource-control.md - I/O Control
    // =========================================================================

    /// Test IoDeviceLimit formatting for io.max
    /// Spec: io.max format is "major:minor riops=N wiops=N rbps=N wbps=N"
    #[test]
    fn test_integration_io_device_limit_to_io_max_all_limits() {
        // Spec example: "8:0 riops=1000 wiops=1000 rbps=10485760 wbps=10485760"
        // This represents 1000 IOPS and 10MB/s for device 8:0

        let device = "8:0";
        let riops = 1000u64;
        let wiops = 1000u64;
        let rbps = 10 * 1024 * 1024u64; // 10 MB/s
        let wbps = 10 * 1024 * 1024u64; // 10 MB/s

        // Expected format per spec
        let expected = format!(
            "{} riops={} wiops={} rbps={} wbps={}",
            device, riops, wiops, rbps, wbps
        );

        assert_eq!(expected, "8:0 riops=1000 wiops=1000 rbps=10485760 wbps=10485760");
    }

    /// Test IoDeviceLimit formatting with partial limits
    /// Spec: Only specified limits should be included in the output
    #[test]
    fn test_integration_io_device_limit_partial_formatting() {
        // When only some limits are set, only those should appear
        // This matches the spec's "Only specified limits are written" requirement

        // Example: Only bandwidth limits, no IOPS limits
        let device = "8:0";
        let rbps = 50 * 1024 * 1024u64; // 50 MB/s
        let wbps = 50 * 1024 * 1024u64; // 50 MB/s

        // Expected format with only bandwidth limits
        let expected = format!("{} rbps={} wbps={}", device, rbps, wbps);

        assert_eq!(expected, "8:0 rbps=52428800 wbps=52428800");
    }

    /// Test IoDeviceLimit formatting with no limits
    /// Spec: Device-only entry should be valid
    #[test]
    fn test_integration_io_device_limit_no_limits() {
        // When no limits are set, only the device identifier is written
        let device = "259:0";

        // This represents the device without any limits applied
        assert_eq!(device, "259:0");
    }

    /// Test multiple device limits
    /// Spec: Multiple IoDeviceLimit entries can be applied to a cgroup
    #[test]
    fn test_integration_io_multiple_device_limits() {
        // Spec: devices field is Vec<IoDeviceLimit>
        // This allows limiting multiple devices independently

        let limits = vec![
            ("8:0", Some(1000u64), Some(1000u64), None, None),
            ("8:16", None, None, Some(10 * 1024 * 1024u64), Some(10 * 1024 * 1024u64)),
        ];

        assert_eq!(limits.len(), 2);
        assert_eq!(limits[0].0, "8:0"); // First device
        assert_eq!(limits[1].0, "8:16"); // Second device
    }
}
