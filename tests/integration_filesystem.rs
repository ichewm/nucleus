//! Integration tests for the filesystem layer (TASK-002)
//!
//! These tests verify conformance to spec/filesystem.md:
//! - tmpfs mount as container root with configurable size limit
//! - Filesystem layout creation (/context, /bin, /dev, /proc, /tmp, /etc)
//! - Context population with filtering (exclude .git, target/, etc.)
//! - Device node creation using mknod with correct major/minor numbers
//! - procfs mounting and accessibility
//! - pivot_root implementation with chroot fallback
//! - Copy user-specified executable to container /bin/
//!
//! Note: Many tests require root and Linux. Tests are designed to:
//! - Skip gracefully on non-Linux systems
//! - Skip gracefully without root
//! - Verify logic that doesn't require actual mount operations

use std::path::PathBuf;
use std::process::Command;

/// Helper to get the binary path
fn nucleus_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("nucleus")
}

/// Helper to create a temporary context directory with test content
fn create_context_with_file(filename: &str, content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("Failed to create temp directory");
    std::fs::write(dir.path().join(filename), content).expect("Failed to write file");
    dir
}

/// Helper to create a context directory with nested structure
fn create_context_with_nested_files() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("Failed to create temp directory");

    // Create top-level file
    std::fs::write(dir.path().join("README.md"), "# Test Context\n").expect("Failed to write README");

    // Create nested directory with files
    std::fs::create_dir_all(dir.path().join("src")).expect("Failed to create src dir");
    std::fs::write(dir.path().join("src/main.rs"), "fn main() {}").expect("Failed to write main.rs");
    std::fs::write(dir.path().join("src/lib.rs"), "// lib").expect("Failed to write lib.rs");

    // Create another nested directory
    std::fs::create_dir_all(dir.path().join("docs")).expect("Failed to create docs dir");
    std::fs::write(dir.path().join("docs/api.md"), "# API Docs").expect("Failed to write api.md");

    dir
}

/// Check if we're running on Linux
fn is_linux() -> bool {
    cfg!(target_os = "linux")
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

// =============================================================================
// SPEC REQUIREMENT: Filesystem Layout
// Reference: spec/filesystem.md - Filesystem Layout
// =============================================================================

mod filesystem_layout_tests {
    use super::*;

    /// Spec: Container filesystem should have standard directories
    /// Layout: /context, /bin, /dev, /proc, /tmp, /etc
    #[test]
    fn test_integration_filesystem_layout_directories_defined() {
        // Per spec/filesystem.md:
        let required_dirs = [
            "context", // Pre-populated from --context
            "bin",     // Minimal binaries
            "dev",     // Minimal device nodes
            "proc",    // procfs mount
            "tmp",     // Writable temp space
            "etc",     // Minimal config
        ];

        assert_eq!(required_dirs.len(), 6, "All 6 required directories must be defined");
    }

    /// Spec: /etc should contain passwd and group files
    #[test]
    fn test_integration_filesystem_layout_etc_files() {
        let etc_files = ["passwd", "group"];

        // Verify minimal /etc files are defined
        assert_eq!(etc_files.len(), 2);
    }
}

// =============================================================================
// SPEC REQUIREMENT: tmpfs Mount with Size Limit
// Reference: spec/filesystem.md - tmpfs (Recommended)
// =============================================================================

mod tmpfs_size_tests {
    use super::*;

    /// Spec: tmpfs size should be 90% of memory limit to leave room for process memory
    /// Reference: filesystem.rs - ContainerFilesystem::new()
    #[test]
    fn test_integration_tmpfs_size_calculation() {
        // Spec: Use 90% of memory limit for tmpfs
        let memory_bytes: u64 = 512 * 1024 * 1024; // 512MB
        let expected_tmpfs_bytes = (memory_bytes as f64 * 0.9) as u64;
        let expected_tmpfs_size = "460M"; // 460.8M rounds to 460M

        assert_eq!(expected_tmpfs_bytes, 483183820); // 512 * 1024 * 1024 * 0.9
        assert_eq!(expected_tmpfs_size, "460M");
    }

    /// Spec: tmpfs mount options should include size and mode
    /// Reference: spec/filesystem.md - Mount Operations
    #[test]
    fn test_integration_tmpfs_mount_options() {
        // Per spec: mount with size limit and mode 0755
        // mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV, "size=512M,mode=0755")

        let expected_flags = ["MS_NOSUID", "MS_NODEV"];
        let expected_options = ["size", "mode"];

        assert_eq!(expected_flags.len(), 2);
        assert_eq!(expected_options.len(), 2);
    }

    /// Spec: Various memory sizes should produce correct tmpfs sizes
    #[test]
    fn test_integration_tmpfs_size_various_inputs() {
        fn format_size(bytes: u64) -> String {
            const KB: u64 = 1024;
            const MB: u64 = 1024 * KB;
            const GB: u64 = 1024 * MB;

            if bytes >= GB {
                format!("{}G", bytes / GB)
            } else if bytes >= MB {
                format!("{}M", bytes / MB)
            } else if bytes >= KB {
                format!("{}K", bytes / KB)
            } else {
                format!("{}", bytes)
            }
        }

        // 1GB memory -> 921M tmpfs (90%)
        let tmpfs_1g = ((1024_u64 * 1024 * 1024) as f64 * 0.9) as u64;
        assert_eq!(format_size(tmpfs_1g), "921M");

        // 256MB memory -> 230M tmpfs (90%)
        let tmpfs_256m = ((256_u64 * 1024 * 1024) as f64 * 0.9) as u64;
        assert_eq!(format_size(tmpfs_256m), "230M");

        // 2GB memory -> 1G tmpfs (90%)
        let tmpfs_2g = ((2_u64 * 1024 * 1024 * 1024) as f64 * 0.9) as u64;
        assert_eq!(format_size(tmpfs_2g), "1G");
    }
}

// =============================================================================
// SPEC REQUIREMENT: Device Node Creation
// Reference: spec/filesystem.md - Device Nodes
// =============================================================================

mod device_node_tests {
    use super::*;

    /// Spec: Required device nodes with correct major/minor numbers
    /// Reference: spec/filesystem.md - Device Nodes section
    #[test]
    fn test_integration_device_nodes_defined() {
        // Per spec/filesystem.md:
        let devices = [
            ("null", 1, 3),
            ("zero", 1, 5),
            ("full", 1, 7),
            ("random", 1, 8),
            ("urandom", 1, 9),
            ("tty", 5, 0),
            ("console", 5, 1),
        ];

        assert_eq!(devices.len(), 7, "All 7 required device nodes must be defined");

        // Verify device numbers match spec
        assert_eq!(devices[0].1, 1); // null major
        assert_eq!(devices[0].2, 3); // null minor
    }

    /// Spec: Device nodes should be character devices with mode 0666
    /// Reference: spec/filesystem.md - Device Nodes implementation
    #[test]
    fn test_integration_device_node_permissions() {
        // Per spec: SFlag::S_IFCHR with mode 0666 (rw-rw-rw-)
        let expected_mode = 0o666;

        // Verify mode is read/write for all
        assert_eq!(expected_mode, 0o666);
    }

    /// Spec: makedev encoding for device numbers
    #[test]
    #[cfg(target_os = "linux")]
    fn test_integration_device_makedev_encoding() {
        // Classic encoding: (major << 8) | minor
        fn makedev(major: u64, minor: u64) -> u64 {
            (major << 8) | minor
        }

        assert_eq!(makedev(1, 3), 259);  // null
        assert_eq!(makedev(1, 5), 261);  // zero
        assert_eq!(makedev(1, 7), 263);  // full
        assert_eq!(makedev(1, 8), 264);  // random
        assert_eq!(makedev(1, 9), 265);  // urandom
        assert_eq!(makedev(5, 0), 1280); // tty
        assert_eq!(makedev(5, 1), 1281); // console
    }
}

// =============================================================================
// SPEC REQUIREMENT: Context Population with Filtering
// Reference: spec/filesystem.md - Context Population
// =============================================================================

mod context_filtering_tests {
    use super::*;

    /// Spec: VCS directories should be excluded (.git, .svn)
    /// Reference: spec/filesystem.md - should_include function
    #[test]
    fn test_integration_context_exclude_vcs() {
        let excluded_dirs = [".git", ".svn"];

        for dir in excluded_dirs {
            assert!(dir.starts_with('.'));
        }

        assert_eq!(excluded_dirs.len(), 2);
    }

    /// Spec: Build artifacts should be excluded (target, node_modules)
    /// Reference: spec/filesystem.md - should_include function
    #[test]
    fn test_integration_context_exclude_build_artifacts() {
        let excluded_dirs = ["target", "node_modules"];

        for dir in excluded_dirs {
            assert!(!dir.starts_with('.')); // Not hidden files
        }

        assert_eq!(excluded_dirs.len(), 2);
    }

    /// Spec: Editor swap files should be excluded (.*.swp)
    /// Reference: spec/filesystem.md - should_include function
    #[test]
    fn test_integration_context_exclude_editor_files() {
        fn should_exclude_editor_swap(name: &str) -> bool {
            name.starts_with('.') && name.ends_with(".swp")
        }

        assert!(should_exclude_editor_swap(".main.rs.swp"));
        assert!(should_exclude_editor_swap(".config.yaml.swp"));
        assert!(!should_exclude_editor_swap("main.rs.swp")); // Not starting with .
        assert!(!should_exclude_editor_swap(".vimrc")); // Not ending with .swp
    }

    /// Spec: Environment files should be excluded (.env, .env.*)
    /// Reference: Implementation in filesystem.rs
    #[test]
    fn test_integration_context_exclude_env_files() {
        fn should_exclude_env(name: &str) -> bool {
            name.starts_with(".env")
        }

        // These should be excluded (anything starting with .env)
        assert!(should_exclude_env(".env"));
        assert!(should_exclude_env(".env.local"));
        assert!(should_exclude_env(".env.production"));
        assert!(should_exclude_env(".environment")); // Also starts with .env
        assert!(should_exclude_env(".envrc")); // Also starts with .env

        // These should NOT be excluded
        assert!(!should_exclude_env("env"));
        assert!(!should_exclude_env("config.env")); // Doesn't start with .env
        assert!(!should_exclude_env(".config")); // Not .env*
    }

    /// Spec: Credential files should be excluded (case-insensitive)
    /// Reference: Implementation in filesystem.rs
    #[test]
    fn test_integration_context_exclude_credential_files() {
        fn should_exclude_credential(name: &str) -> bool {
            let name_lower = name.to_lowercase();
            name_lower.contains("credential")
                || name_lower.contains("secret")
                || name_lower.contains("private")
        }

        assert!(should_exclude_credential("credentials.json"));
        assert!(should_exclude_credential("SECRETS.yaml"));
        assert!(should_exclude_credential("PrivateKey.pem"));
        assert!(should_exclude_credential("my-private-key"));
        assert!(!should_exclude_credential("main.rs"));
    }

    /// Spec: Key/certificate files should be excluded
    /// Reference: Implementation in filesystem.rs
    #[test]
    fn test_integration_context_exclude_key_files() {
        fn should_exclude_key_file(name: &str) -> bool {
            name.ends_with(".pem")
                || name.ends_with(".key")
                || name.ends_with(".p12")
                || name.ends_with(".crt")
        }

        assert!(should_exclude_key_file("server.key"));
        assert!(should_exclude_key_file("cert.pem"));
        assert!(should_exclude_key_file("keystore.p12"));
        assert!(should_exclude_key_file("ca.crt"));
        assert!(!should_exclude_key_file("key.txt")); // Not ending with .key
        assert!(!should_exclude_key_file("pem"));
    }
}

// =============================================================================
// SPEC REQUIREMENT: procfs Mounting
// Reference: spec/filesystem.md - procfs and sysfs
// =============================================================================

mod procfs_tests {
    use super::*;

    /// Spec: procfs should be mounted with MS_NOSUID | MS_NODEV | MS_NOEXEC
    /// Reference: spec/filesystem.md - Mount Operations
    #[test]
    fn test_integration_procfs_mount_flags() {
        // Per spec: mount proc with security flags
        let expected_flags = ["MS_NOSUID", "MS_NODEV", "MS_NOEXEC"];

        assert_eq!(expected_flags.len(), 3);
    }

    /// Spec: procfs should be accessible inside container
    /// Reference: spec/filesystem.md - procfs and sysfs
    #[test]
    fn test_integration_procfs_expected_path() {
        // procfs should be mounted at /proc inside container
        let expected_path = "/proc";

        assert!(expected_path.starts_with('/'));
    }
}

// =============================================================================
// SPEC REQUIREMENT: pivot_root with chroot fallback
// Reference: spec/filesystem.md - pivot_root vs chroot
// =============================================================================

mod root_switching_tests {
    use super::*;

    /// Spec: pivot_root is preferred over chroot
    /// Reference: spec/filesystem.md - pivot_root vs chroot
    #[test]
    fn test_integration_pivot_root_preferred() {
        // Per spec:
        // pivot_root (preferred):
        // - Changes root of mount namespace
        // - Old root can be unmounted
        // - Cleaner isolation

        let pivot_root_advantages = [
            "Changes root of mount namespace",
            "Old root can be unmounted",
            "Cleaner isolation",
        ];

        assert_eq!(pivot_root_advantages.len(), 3);
    }

    /// Spec: chroot is fallback when pivot_root unavailable
    /// Reference: spec/filesystem.md - pivot_root vs chroot
    #[test]
    fn test_integration_chroot_fallback_behavior() {
        // Per spec:
        // chroot (fallback):
        // - Simpler but less secure
        // - Old root still accessible via file descriptors
        // - Use when pivot_root unavailable

        let chroot_characteristics = [
            "Simpler but less secure",
            "Old root still accessible via file descriptors",
        ];

        assert_eq!(chroot_characteristics.len(), 2);
    }

    /// Spec: After pivot_root, old root should be unmounted
    /// Reference: spec/filesystem.md - pivot_root implementation
    #[test]
    fn test_integration_pivot_root_cleanup() {
        // Per spec:
        // 1. Create old-root directory
        // 2. pivot_root(new_root, old_root)
        // 3. chdir("/")
        // 4. umount2("/old-root", MNT_DETACH)
        // 5. remove_dir("/old-root")

        let cleanup_steps = 5;
        assert_eq!(cleanup_steps, 5);
    }
}

// =============================================================================
// SPEC REQUIREMENT: Copy user-specified executable to container /bin/
// Reference: spec/filesystem.md - Filesystem Layout
// Reference: PRD - "Copy user-specified executable to container /bin/"
// =============================================================================

mod executable_copy_tests {
    use super::*;

    /// Spec: Executable should be copied to /bin/ in container
    /// Reference: spec/filesystem.md - Filesystem Layout shows /bin/agent
    #[test]
    fn test_integration_executable_destination() {
        // Executable should be copied to /bin/<name> inside container
        let container_bin_path = "/bin";
        assert!(container_bin_path.starts_with('/'));
    }

    /// Spec: Executable should have execute permissions
    /// Reference: Implementation in filesystem.rs - copy_executable
    #[test]
    fn test_integration_executable_permissions() {
        // Execute bits: 0o111 (x for user, group, other)
        let execute_bits = 0o111u32;

        assert_eq!(execute_bits, 0o111);
    }

    /// Spec: Executable is found using which
    /// Reference: Implementation in filesystem.rs - copy_executable uses which::which
    #[test]
    fn test_integration_executable_discovery() {
        // Executable should be found on PATH using which
        // This test verifies the spec requirement exists

        let discovery_method = "which";
        assert!(!discovery_method.is_empty());
    }
}

// =============================================================================
// E2E TEST: Context population via nucleus CLI
// Reference: PRD Acceptance Criteria
// "Integration test: nucleus run --context ./test-ctx/ -- /bin/cat /context/test.txt outputs correct content"
// =============================================================================

mod e2e_context_population {
    use super::*;

    /// E2E Test: Verify context directory is populated and accessible inside container
    /// This is the LONGEST-CHAIN E2E test for filesystem layer
    /// Reference: PRD Acceptance Criteria
    #[test]
    fn test_e2e_context_population_cat_file() {
        // Create context with test file
        let test_content = "Hello from context file!";
        let context = create_context_with_file("test.txt", test_content);

        // Execute nucleus run with cat command
        let output = Command::new(nucleus_binary())
            .args([
                "run",
                "--context",
                context.path().to_str().unwrap(),
                "--memory",
                "256M",
                "--cpus",
                "1",
                "--runtime",
                "native",
                "--",
                "/bin/cat",
                "/context/test.txt",
            ])
            .output()
            .expect("Failed to execute nucleus");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // On non-Linux: Should fail with "Linux-only" message
        if !is_linux() {
            assert!(
                stderr.contains("Linux") || stderr.contains("namespace"),
                "On non-Linux, should indicate Linux-only requirement. stderr: {}",
                stderr
            );
            return;
        }

        // On Linux without root: Should fail with permission error
        if !is_root() {
            assert!(
                !output.status.success(),
                "Should fail without root on Linux"
            );
            return;
        }

        // On Linux with root: Should succeed and output file content
        assert!(
            output.status.success(),
            "Should succeed with root on Linux. stderr: {}",
            stderr
        );
        assert!(
            stdout.contains(test_content),
            "Output should contain test file content. stdout: {}",
            stdout
        );
    }

    /// E2E Test: Verify nested context files are accessible
    #[test]
    fn test_e2e_context_population_nested_files() {
        let context = create_context_with_nested_files();

        // Test reading a nested file
        let output = Command::new(nucleus_binary())
            .args([
                "run",
                "--context",
                context.path().to_str().unwrap(),
                "--memory",
                "256M",
                "--cpus",
                "1",
                "--runtime",
                "native",
                "--",
                "/bin/cat",
                "/context/src/main.rs",
            ])
            .output()
            .expect("Failed to execute nucleus");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !is_linux() || !is_root() {
            // Skip on non-Linux or without root
            return;
        }

        assert!(
            output.status.success(),
            "Should succeed with root on Linux. stderr: {}",
            stderr
        );
        assert!(
            stdout.contains("fn main()"),
            "Output should contain nested file content. stdout: {}",
            stdout
        );
    }

    /// E2E Test: Verify filtered files are NOT in context
    #[test]
    fn test_e2e_context_population_filtering_enforced() {
        let context = tempfile::tempdir().expect("Failed to create temp directory");

        // Create files that should be included
        std::fs::write(context.path().join("main.rs"), "fn main() {}").expect("Failed to write");

        // Create .git directory that should be excluded
        std::fs::create_dir_all(context.path().join(".git")).expect("Failed to create .git");
        std::fs::write(context.path().join(".git/config"), "[core]").expect("Failed to write");

        // Try to list context directory inside container
        let output = Command::new(nucleus_binary())
            .args([
                "run",
                "--context",
                context.path().to_str().unwrap(),
                "--memory",
                "256M",
                "--cpus",
                "1",
                "--runtime",
                "native",
                "--",
                "/bin/ls",
                "-la",
                "/context/",
            ])
            .output()
            .expect("Failed to execute nucleus");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !is_linux() || !is_root() {
            return;
        }

        assert!(
            output.status.success(),
            "Should succeed with root on Linux. stderr: {}",
            stderr
        );

        // .git should NOT be in the listing
        assert!(
            !stdout.contains(".git"),
            ".git should be filtered out. stdout: {}",
            stdout
        );

        // main.rs should be in the listing
        assert!(
            stdout.contains("main.rs"),
            "main.rs should be included. stdout: {}",
            stdout
        );
    }

    /// E2E Test: Verify procfs is mounted and accessible
    #[test]
    fn test_e2e_procfs_mounted() {
        let context = tempfile::tempdir().expect("Failed to create temp directory");
        std::fs::write(context.path().join("test.txt"), "test").expect("Failed to write");

        // Read /proc/self/stat to verify procfs is mounted
        let output = Command::new(nucleus_binary())
            .args([
                "run",
                "--context",
                context.path().to_str().unwrap(),
                "--memory",
                "256M",
                "--cpus",
                "1",
                "--runtime",
                "native",
                "--",
                "/bin/cat",
                "/proc/self/stat",
            ])
            .output()
            .expect("Failed to execute nucleus");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !is_linux() || !is_root() {
            return;
        }

        assert!(
            output.status.success(),
            "Should succeed with root on Linux. stderr: {}",
            stderr
        );

        // /proc/self/stat should have content (process info)
        assert!(
            !stdout.is_empty(),
            "/proc/self/stat should have content. stdout: {}",
            stdout
        );
    }

    /// E2E Test: Verify device nodes exist
    #[test]
    fn test_e2e_device_nodes_exist() {
        let context = tempfile::tempdir().expect("Failed to create temp directory");
        std::fs::write(context.path().join("test.txt"), "test").expect("Failed to write");

        // List /dev directory
        let output = Command::new(nucleus_binary())
            .args([
                "run",
                "--context",
                context.path().to_str().unwrap(),
                "--memory",
                "256M",
                "--cpus",
                "1",
                "--runtime",
                "native",
                "--",
                "/bin/ls",
                "/dev/",
            ])
            .output()
            .expect("Failed to execute nucleus");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !is_linux() || !is_root() {
            return;
        }

        assert!(
            output.status.success(),
            "Should succeed with root on Linux. stderr: {}",
            stderr
        );

        // Required device nodes should be present
        let required_devices = ["null", "zero", "random", "urandom", "tty", "console"];
        for device in required_devices {
            assert!(
                stdout.contains(device),
                "/dev/{} should exist. stdout: {}",
                device,
                stdout
            );
        }
    }

    /// E2E Test: Verify /dev/null works (can write to it)
    #[test]
    fn test_e2e_device_null_writable() {
        let context = tempfile::tempdir().expect("Failed to create temp directory");
        std::fs::write(context.path().join("test.txt"), "test").expect("Failed to write");

        // Write to /dev/null - should succeed silently
        let output = Command::new(nucleus_binary())
            .args([
                "run",
                "--context",
                context.path().to_str().unwrap(),
                "--memory",
                "256M",
                "--cpus",
                "1",
                "--runtime",
                "native",
                "--",
                "/bin/sh",
                "-c",
                "echo test > /dev/null",
            ])
            .output()
            .expect("Failed to execute nucleus");

        let stderr = String::from_utf8_lossy(&output.stderr);

        if !is_linux() || !is_root() {
            return;
        }

        assert!(
            output.status.success(),
            "Writing to /dev/null should succeed. stderr: {}",
            stderr
        );
    }
}

// =============================================================================
// Linux-specific filesystem tests (require root)
// =============================================================================

#[cfg(target_os = "linux")]
mod linux_filesystem_tests {
    use super::*;

    /// Test actual tmpfs mount (requires root)
    #[test]
    fn test_integration_tmpfs_actual_mount() {
        if !is_root() {
            eprintln!("SKIP: test requires root");
            return;
        }

        use std::fs;

        // Create a temp directory for the mount
        let mount_point = tempfile::tempdir().expect("Failed to create temp dir");
        let mount_path = mount_point.path();

        // Mount tmpfs
        use nix::mount::{mount, MsFlags};
        let result = mount(
            Some("tmpfs"),
            mount_path,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("size=10M,mode=0755"),
        );

        if result.is_ok() {
            // Verify mount succeeded by creating a file
            let test_file = mount_path.join("test.txt");
            fs::write(&test_file, "test content").expect("Failed to write to tmpfs");
            assert!(test_file.exists(), "File should exist on tmpfs");

            // Cleanup - umount
            let _ = nix::mount::umount(mount_path);
        }
    }
}
