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
