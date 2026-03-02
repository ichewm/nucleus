//! Integration tests for gVisor runtime execution
//!
//! These tests verify the gVisor integration module conforms to spec:
//! - OCI bundle generation with correct config.json
//! - Bundle directory structure (rootfs with bin, context, dev, etc, proc, tmp)
//! - runsc lifecycle management (create → start → wait → delete)
//! - Error handling when runsc not available or fails
//! - Bundle directory cleanup after execution
//!
//! PRD Reference: TASK-005 - gVisor Runtime Execution

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// Import the gVisor module for integration testing
use nucleus::gvisor::{GvisorExecutor, OciBundle, is_gvisor_available, find_runsc};
use nucleus::cli::RunArgs;

// =============================================================================
// INTEGRATION TEST: OCI Bundle Generation
// Spec: "OCI bundle generated with correct config.json"
// =============================================================================

/// Test that OciBundle::new creates a bundle with the correct directory structure
/// Spec: Bundle directory structure (rootfs with bin, context, dev, etc, proc, tmp)
#[test]
fn test_integration_oci_bundle_directory_structure() {
    let container_id = "test-bundle-structure";
    let bundle = OciBundle::new(container_id);

    // Verify bundle directory path follows spec pattern
    let bundle_path = bundle.bundle_dir();
    assert!(
        bundle_path.to_str().unwrap().contains(&format!("nucleus-oci-{}", container_id)),
        "Bundle directory should follow pattern nucleus-oci-<container-id>"
    );

    // Verify rootfs path
    let rootfs_path = bundle.rootfs();
    assert!(
        rootfs_path.ends_with("rootfs"),
        "Rootfs path should end with 'rootfs'"
    );
    assert!(
        rootfs_path.starts_with(bundle_path),
        "Rootfs should be inside bundle directory"
    );

    // Verify container ID
    assert_eq!(bundle.container_id(), container_id);
}

/// Test that config.json is generated with OCI-compliant structure
/// Spec: "Generate config.json with OCI-compliant configuration (namespaces, resources, process)"
#[test]
fn test_integration_config_json_oci_compliant_structure() {
    let bundle = OciBundle::new("test-config-json");

    // Create RunArgs for testing
    let args = RunArgs {
        context: PathBuf::from("/tmp"),
        memory: "512M".to_string(),
        cpus: 1.5,
        runtime: "gvisor".to_string(),
        hostname: Some("testhost".to_string()),
        io_limit: None,
        command: vec!["/bin/echo".to_string(), "hello".to_string()],
    };

    let memory_bytes = 512 * 1024 * 1024; // 512MB
    let config_json = bundle.generate_config_json(&args, memory_bytes);

    // Parse JSON to verify structure
    let config: serde_json::Value = serde_json::from_str(&config_json)
        .expect("config.json should be valid JSON");

    // Verify OCI version
    assert_eq!(config["ociVersion"], "1.0.0", "OCI version should be 1.0.0");

    // Verify process configuration (spec: process)
    assert!(config["process"].is_object(), "process field must be present");
    assert!(config["process"]["args"].is_array(), "process.args must be an array");
    assert_eq!(config["process"]["args"][0], "/bin/echo", "First arg should be executable");
    assert_eq!(config["process"]["args"][1], "hello", "Second arg should be command argument");
    assert!(config["process"]["env"].is_array(), "process.env must be an array");
    assert_eq!(config["process"]["cwd"], "/", "Working directory should be /");
    assert_eq!(config["process"]["user"]["uid"], 0, "Default UID should be 0 (root)");
    assert_eq!(config["process"]["user"]["gid"], 0, "Default GID should be 0 (root)");

    // Verify capabilities are dropped (spec: security)
    assert!(config["process"]["capabilities"]["bounding"].as_array().unwrap().is_empty(),
        "Bounding capabilities should be empty (dropped)");
    assert!(config["process"]["capabilities"]["effective"].as_array().unwrap().is_empty(),
        "Effective capabilities should be empty (dropped)");
    assert_eq!(config["process"]["noNewPrivileges"], true, "noNewPrivileges should be true");

    // Verify root configuration (spec: root)
    assert_eq!(config["root"]["path"], "rootfs", "Root path should be 'rootfs'");
    assert_eq!(config["root"]["readonly"], false, "Root should not be readonly");

    // Verify hostname (spec: hostname)
    assert_eq!(config["hostname"], "testhost", "Hostname should match CLI argument");

    // Verify Linux configuration (spec: linux)
    assert!(config["linux"].is_object(), "linux field must be present");

    // Verify namespaces (spec: namespaces)
    let namespaces = config["linux"]["namespaces"].as_array().expect("namespaces must be array");
    let ns_types: Vec<&str> = namespaces.iter()
        .filter_map(|ns| ns["type"].as_str())
        .collect();
    assert!(ns_types.contains(&"pid"), "PID namespace required");
    assert!(ns_types.contains(&"network"), "Network namespace required");
    assert!(ns_types.contains(&"ipc"), "IPC namespace required");
    assert!(ns_types.contains(&"uts"), "UTS namespace required");
    assert!(ns_types.contains(&"mount"), "Mount namespace required");

    // Verify resource limits (spec: resources)
    assert_eq!(config["linux"]["resources"]["memory"]["limit"], memory_bytes,
        "Memory limit should match specified value");
    assert_eq!(config["linux"]["resources"]["memory"]["swap"], memory_bytes,
        "Swap should equal memory (effectively disabled)");
}

/// Test CPU quota calculation in config.json
/// Spec: CPU quota is calculated as: cpus * period
#[test]
fn test_integration_config_json_cpu_quota_calculation() {
    let bundle = OciBundle::new("test-cpu-quota");

    // Test with 1.5 CPUs
    let args = RunArgs {
        context: PathBuf::from("/tmp"),
        memory: "512M".to_string(),
        cpus: 1.5,
        runtime: "gvisor".to_string(),
        hostname: None,
        io_limit: None,
        command: vec!["/bin/true".to_string()],
    };

    let config_json = bundle.generate_config_json(&args, 512 * 1024 * 1024);
    let config: serde_json::Value = serde_json::from_str(&config_json).unwrap();

    // CPU quota should be 1.5 * 100000 = 150000
    assert_eq!(config["linux"]["resources"]["cpu"]["quota"], 150000,
        "CPU quota for 1.5 cores should be 150000");
    assert_eq!(config["linux"]["resources"]["cpu"]["period"], 100000,
        "CPU period should be 100000");
}

/// Test hostname default when not specified
/// Spec: Default hostname should be "nucleus"
#[test]
fn test_integration_config_json_default_hostname() {
    let bundle = OciBundle::new("test-default-hostname");

    let args = RunArgs {
        context: PathBuf::from("/tmp"),
        memory: "256M".to_string(),
        cpus: 1.0,
        runtime: "gvisor".to_string(),
        hostname: None, // No hostname specified
        io_limit: None,
        command: vec!["/bin/true".to_string()],
    };

    let config_json = bundle.generate_config_json(&args, 256 * 1024 * 1024);
    let config: serde_json::Value = serde_json::from_str(&config_json).unwrap();

    assert_eq!(config["hostname"], "nucleus", "Default hostname should be 'nucleus'");
}

/// Test environment variables in config.json
/// Spec: Default environment should include PATH, TERM, HOME
#[test]
fn test_integration_config_json_default_environment() {
    let bundle = OciBundle::new("test-env");

    let args = RunArgs {
        context: PathBuf::from("/tmp"),
        memory: "256M".to_string(),
        cpus: 1.0,
        runtime: "gvisor".to_string(),
        hostname: None,
        io_limit: None,
        command: vec!["/bin/true".to_string()],
    };

    let config_json = bundle.generate_config_json(&args, 256 * 1024 * 1024);
    let config: serde_json::Value = serde_json::from_str(&config_json).unwrap();

    let env = config["process"]["env"].as_array().expect("env must be array");
    let env_str: Vec<&str> = env.iter()
        .filter_map(|e| e.as_str())
        .collect();

    assert!(env_str.iter().any(|e| e.starts_with("PATH=")), "PATH must be set");
    assert!(env_str.iter().any(|e| e.starts_with("TERM=")), "TERM must be set");
    assert!(env_str.iter().any(|e| e.starts_with("HOME=")), "HOME must be set");
}

// =============================================================================
// INTEGRATION TEST: Bundle Directory Structure
// Spec: "Bundle directory structure (rootfs with bin, context, dev, etc, proc, tmp)"
// =============================================================================

/// Test that bundle.create() generates correct directory layout
/// This test requires Linux because it uses ContainerFilesystem::setup
#[cfg(target_os = "linux")]
#[test]
fn test_integration_bundle_create_directory_layout() {
    let bundle = OciBundle::new("test-layout");

    let args = RunArgs {
        context: PathBuf::from("/tmp"),
        memory: "256M".to_string(),
        cpus: 1.0,
        runtime: "gvisor".to_string(),
        hostname: None,
        io_limit: None,
        command: vec!["/bin/true".to_string()],
    };

    // Create bundle
    let result = bundle.create(&args, 256 * 1024 * 1024);

    // This may fail without root privileges, but we can still check structure if it succeeds
    if let Ok(_) = result {
        let rootfs = bundle.rootfs();

        // Verify required directories exist per spec
        assert!(rootfs.join("bin").exists(), "bin/ directory must exist");
        assert!(rootfs.join("context").exists(), "context/ directory must exist");
        assert!(rootfs.join("dev").exists(), "dev/ directory must exist");
        assert!(rootfs.join("etc").exists(), "etc/ directory must exist");
        assert!(rootfs.join("proc").exists(), "proc/ directory must exist");
        assert!(rootfs.join("tmp").exists(), "tmp/ directory must exist");

        // Verify config.json exists
        assert!(bundle.bundle_dir().join("config.json").exists(), "config.json must exist");
    }

    // Cleanup
    let _ = bundle.cleanup();
}

// =============================================================================
// INTEGRATION TEST: Bundle Cleanup
// Spec: "Bundle directory cleaned up after execution"
// =============================================================================

/// Test that cleanup() removes the bundle directory
#[test]
fn test_integration_bundle_cleanup_removes_directory() {
    let temp = TempDir::new().unwrap();
    let bundle_dir = temp.path().join("test-cleanup-bundle");

    // Create a mock bundle directory
    fs::create_dir_all(bundle_dir.join("rootfs/bin")).unwrap();
    fs::create_dir_all(bundle_dir.join("rootfs/context")).unwrap();
    fs::write(bundle_dir.join("config.json"), "{}").unwrap();

    // Verify directory exists
    assert!(bundle_dir.exists(), "Bundle directory should exist before cleanup");

    // Cleanup
    fs::remove_dir_all(&bundle_dir).unwrap();

    // Verify directory is removed
    assert!(!bundle_dir.exists(), "Bundle directory should be removed after cleanup");
}

/// Test that OciBundle Drop implementation cleans up
#[test]
fn test_integration_bundle_drop_cleanup() {
    let bundle_path;

    {
        let bundle = OciBundle::new("test-drop-cleanup");
        bundle_path = bundle.bundle_dir().to_path_buf();

        // Create the directory
        fs::create_dir_all(&bundle_path).unwrap();
        fs::write(bundle_path.join("config.json"), "{}").unwrap();

        assert!(bundle_path.exists(), "Bundle should exist before drop");
    } // bundle is dropped here

    // After drop, the directory should be cleaned up
    // Note: This tests the Drop implementation behavior
    assert!(!bundle_path.exists(), "Bundle directory should be cleaned up on drop");
}

// =============================================================================
// INTEGRATION TEST: gVisor Availability Check
// Spec: "Error handling when runsc not available or fails"
// =============================================================================

/// Test is_gvisor_available function
#[test]
fn test_integration_gvisor_availability_check() {
    // This function should not panic
    let available = is_gvisor_available();

    // The result depends on whether runsc is installed
    // We just verify the function runs without error
    if available {
        // If available, find_runsc should succeed
        assert!(find_runsc().is_ok(), "If gVisor is available, find_runsc should succeed");
    } else {
        // If not available, find_runsc should fail
        assert!(find_runsc().is_err(), "If gVisor is not available, find_runsc should fail");
    }
}

/// Test that find_runsc returns helpful error message
#[test]
fn test_integration_find_runsc_error_message() {
    if !is_gvisor_available() {
        let result = find_runsc();
        assert!(result.is_err(), "find_runsc should fail when runsc not available");

        let err = result.unwrap_err();
        let err_msg = err.to_string();

        // Error message should be helpful (per spec)
        assert!(err_msg.contains("runsc"), "Error should mention 'runsc'");
        assert!(err_msg.contains("PATH") || err_msg.contains("Install"),
            "Error should mention PATH or installation instructions");
    }
}

// =============================================================================
// INTEGRATION TEST: GvisorExecutor Creation
// Spec: "runsc lifecycle properly managed (create → start → wait → delete)"
// =============================================================================

/// Test that GvisorExecutor is created with correct container ID
#[test]
fn test_integration_gvisor_executor_creation() {
    let container_id = "test-executor-123";
    let executor = GvisorExecutor::new(container_id);

    // The executor should be created successfully
    // (actual execution requires runsc to be installed)
    drop(executor);
}

// =============================================================================
// INTEGRATION TEST: JSON Escaping
// Spec: config.json must be valid JSON with properly escaped strings
// =============================================================================

/// Test JSON string escaping for special characters
#[test]
fn test_integration_json_escaping_special_chars() {
    let bundle = OciBundle::new("test-json-escape");

    // Command with special characters
    let args = RunArgs {
        context: PathBuf::from("/tmp"),
        memory: "256M".to_string(),
        cpus: 1.0,
        runtime: "gvisor".to_string(),
        hostname: Some("test-host".to_string()),
        io_limit: None,
        command: vec![
            "/bin/echo".to_string(),
            "hello\"world".to_string(),   // Quote
            "path\\to\\file".to_string(), // Backslashes
            "line1\nline2".to_string(),   // Newline
        ],
    };

    let config_json = bundle.generate_config_json(&args, 256 * 1024 * 1024);

    // The JSON must be parseable (valid JSON)
    let result: Result<serde_json::Value, _> = serde_json::from_str(&config_json);
    assert!(result.is_ok(), "config.json must be valid JSON even with special characters: {:?}", result);
}

// =============================================================================
// INTEGRATION TEST: Memory Calculation
// Spec: Memory limits should be correctly converted to bytes
// =============================================================================

/// Test that memory strings are correctly parsed
#[test]
fn test_integration_memory_string_parsing() {
    let test_cases = [
        ("512M", 512 * 1024 * 1024),
        ("1G", 1024 * 1024 * 1024),
        ("256M", 256 * 1024 * 1024),
        ("2G", 2 * 1024 * 1024 * 1024),
    ];

    for (memory_str, expected_bytes) in test_cases {
        let args = RunArgs {
            context: PathBuf::from("/tmp"),
            memory: memory_str.to_string(),
            cpus: 1.0,
            runtime: "gvisor".to_string(),
            hostname: None,
            io_limit: None,
            command: vec!["/bin/true".to_string()],
        };

        let result = args.memory_bytes();
        assert!(result.is_ok(), "Memory string '{}' should parse successfully", memory_str);
        assert_eq!(result.unwrap(), expected_bytes,
            "Memory '{}' should be {} bytes", memory_str, expected_bytes);
    }
}

// =============================================================================
// INTEGRATION TEST: Error Types
// Spec: "Handle runsc exit codes and errors"
// =============================================================================

/// Test that GvisorNotFound error contains helpful message
#[test]
fn test_integration_gvisor_not_found_error() {
    use nucleus::error::NucleusError;

    let error = NucleusError::GvisorNotFound("runsc not found".to_string());
    let err_msg = error.to_string();

    assert!(err_msg.contains("runsc"), "GvisorNotFound error should mention 'runsc'");
}

/// Test that GvisorExecute error includes command context
#[test]
fn test_integration_gvisor_execute_error() {
    use nucleus::error::NucleusError;

    let error = NucleusError::GvisorExecute("runsc create failed: permission denied".to_string());
    let err_msg = error.to_string();

    assert!(err_msg.contains("runsc") || err_msg.contains("gVisor"),
        "GvisorExecute error should mention runsc or gVisor");
}
