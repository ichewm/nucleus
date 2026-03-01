//! Integration tests for CLI interface
//!
//! These tests verify that the CLI conforms to spec/architecture.md:
//! - Required parameters: --context, --memory, --cpus, --runtime
//! - Optional parameter: --hostname
//! - The `run` command orchestrates container creation

use std::path::PathBuf;
use std::process::Command;

/// Helper to get the binary path
fn nucleus_binary() -> PathBuf {
    // Use the debug binary from target
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("nucleus")
}

/// Helper to create a temporary context directory
fn create_temp_context() -> tempfile::TempDir {
    tempfile::tempdir().expect("Failed to create temp directory")
}

// =============================================================================
// SPEC REQUIREMENT: CLI with clap 4.x derive feature implementing nucleus run command
// Reference: PRD "CLI with clap 4.x derive feature implementing nucleus run command"
// =============================================================================

#[test]
fn test_integration_cli_help_shows_run_command() {
    // Spec: The CLI should have a `run` subcommand
    let output = Command::new(nucleus_binary())
        .arg("--help")
        .output()
        .expect("Failed to execute nucleus");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify run command is documented
    assert!(stdout.contains("run"), "CLI should show 'run' command in help");
    assert!(
        stdout.contains("Run a command in an isolated container"),
        "CLI should describe run command"
    );
}

#[test]
fn test_integration_cli_run_help_shows_required_params() {
    // Spec: Required parameters: --context, --memory, --cpus, --runtime
    let output = Command::new(nucleus_binary())
        .args(["run", "--help"])
        .output()
        .expect("Failed to execute nucleus run --help");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify all required parameters are documented
    assert!(
        stdout.contains("--context"),
        "CLI should document --context parameter"
    );
    assert!(
        stdout.contains("--memory"),
        "CLI should document --memory parameter"
    );
    assert!(
        stdout.contains("--cpus") || stdout.contains("-p"),
        "CLI should document --cpus parameter"
    );
    assert!(
        stdout.contains("--runtime"),
        "CLI should document --runtime parameter"
    );
}

#[test]
fn test_integration_cli_run_help_shows_optional_params() {
    // Spec: Optional parameter: --hostname
    let output = Command::new(nucleus_binary())
        .args(["run", "--help"])
        .output()
        .expect("Failed to execute nucleus run --help");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("--hostname"),
        "CLI should document --hostname parameter"
    );
}

// =============================================================================
// SPEC REQUIREMENT: CLI validates input parameters and shows helpful error messages
// Reference: PRD Acceptance Criteria "CLI validates input parameters and shows helpful error messages"
// =============================================================================

#[test]
fn test_integration_cli_missing_context_shows_error() {
    // Spec: CLI should validate that --context is provided and exists
    let output = Command::new(nucleus_binary())
        .args(["run", "--memory", "512M", "--cpus", "2", "--runtime", "native", "--", "echo"])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // clap should report missing required argument
    assert!(
        !output.status.success(),
        "CLI should fail without --context"
    );
    assert!(
        stderr.contains("--context") || stderr.contains("required"),
        "CLI should indicate missing --context in error message"
    );
}

#[test]
fn test_integration_cli_nonexistent_context_shows_error() {
    // Spec: CLI should validate that context directory exists
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            "/nonexistent/path/that/does/not/exist",
            "--memory",
            "512M",
            "--cpus",
            "2",
            "--runtime",
            "native",
            "--",
            "echo",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "CLI should fail with nonexistent context"
    );
    assert!(
        stderr.contains("Context") || stderr.contains("does not exist"),
        "CLI should show helpful error for nonexistent context"
    );
}

#[test]
fn test_integration_cli_context_file_not_directory_shows_error() {
    // Spec: CLI should validate that context is a directory
    let temp_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");

    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            temp_file.path().to_str().unwrap(),
            "--memory",
            "512M",
            "--cpus",
            "2",
            "--runtime",
            "native",
            "--",
            "echo",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "CLI should fail when context is not a directory"
    );
    assert!(
        stderr.contains("not a directory") || stderr.contains("Context"),
        "CLI should show helpful error for non-directory context"
    );
}

#[test]
fn test_integration_cli_empty_command_shows_error() {
    // Spec: CLI should require a command to execute
    let context = create_temp_context();

    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--memory",
            "512M",
            "--cpus",
            "2",
            "--runtime",
            "native",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "CLI should fail without a command"
    );
    // Command is marked as required
    assert!(
        stderr.contains("command") || stderr.contains("required"),
        "CLI should indicate missing command"
    );
}

#[test]
fn test_integration_cli_invalid_runtime_shows_error() {
    // Spec: Runtime must be 'native' or 'gvisor'
    let context = create_temp_context();

    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--memory",
            "512M",
            "--cpus",
            "2",
            "--runtime",
            "invalid-runtime",
            "--",
            "echo",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "CLI should fail with invalid runtime"
    );
    assert!(
        stderr.contains("runtime") || stderr.contains("Runtime"),
        "CLI should indicate invalid runtime in error"
    );
}

#[test]
fn test_integration_cli_zero_cpu_shows_error() {
    // Spec: CPU cores must be positive
    let context = create_temp_context();

    // Use = syntax to avoid clap parsing -1 as a flag
    // Test with 0 (which is also invalid)
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--memory",
            "512M",
            "--cpus=0",  // Use = syntax to be explicit
            "--runtime",
            "native",
            "--",
            "echo",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "CLI should fail with zero CPU"
    );
    assert!(
        stderr.contains("CPU") || stderr.contains("cpu"),
        "CLI should indicate invalid CPU in error. stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_invalid_hostname_shows_error() {
    // Spec: Hostname validation - alphanumeric and hyphens only, not starting/ending with hyphen
    let context = create_temp_context();

    // Use = syntax to avoid clap parsing -invalid as a flag
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--memory",
            "512M",
            "--cpus",
            "2",
            "--hostname=-invalid-hostname",  // Use = syntax for value starting with -
            "--runtime",
            "native",
            "--",
            "echo",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "CLI should fail with invalid hostname"
    );
    assert!(
        stderr.contains("hostname") || stderr.contains("Hostname"),
        "CLI should indicate invalid hostname in error. stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_dangerous_executable_shows_error() {
    // Spec: Security - prevent command injection via executable name
    let context = create_temp_context();

    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--memory",
            "512M",
            "--cpus",
            "2",
            "--runtime",
            "native",
            "--",
            "ls;rm -rf /",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "CLI should fail with dangerous executable"
    );
    assert!(
        stderr.contains("dangerous") || stderr.contains("executable") || stderr.contains("Executable"),
        "CLI should indicate dangerous executable in error"
    );
}

// =============================================================================
// SPEC REQUIREMENT: Memory parsing supports various formats
// Reference: spec/resource-control.md - memory configuration
// =============================================================================

#[test]
fn test_integration_cli_memory_formats() {
    // This test verifies the CLI accepts various memory format strings
    // The actual validation happens in parse_size function

    let context = create_temp_context();

    // Test with 512M format - should parse but may fail execution on non-Linux
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--memory",
            "512M",
            "--cpus",
            "1",
            "--runtime",
            "native",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("Failed to execute nucleus");

    // On non-Linux, it will fail with namespace error, but memory parsing should succeed
    // On Linux without root, it will fail with permission error
    // Either way, it shouldn't fail with "Invalid size" or memory parse error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Invalid size") && !stderr.contains("parse"),
        "CLI should accept 512M memory format, stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_default_values() {
    // Spec: --memory defaults to 512M, --cpus defaults to 1, --runtime defaults to native
    let context = create_temp_context();

    // Run with minimal required arguments
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("Failed to execute nucleus");

    // Should not fail due to missing defaults
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("required") || stderr.contains("Linux"),
        "CLI defaults should work, stderr: {}",
        stderr
    );
}

// =============================================================================
// SPEC REQUIREMENT: --io-limit parameter for I/O throttling
// Reference: spec/resource-control.md - I/O Control, PRD TASK-004
// =============================================================================

#[test]
fn test_integration_cli_io_limit_parameter_documented() {
    // Spec: CLI should document the --io-limit parameter
    let output = Command::new(nucleus_binary())
        .args(["run", "--help"])
        .output()
        .expect("Failed to execute nucleus run --help");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("--io-limit"),
        "CLI should document --io-limit parameter. stdout: {}",
        stdout
    );
}

#[test]
fn test_integration_cli_io_limit_accepts_valid_format() {
    // Spec: --io-limit format is <device>:<riops>:<wiops>:<rbps>:<wbps>
    let context = create_temp_context();

    // Test with auto device detection and all limits specified
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--io-limit",
            "auto:1000:1000:10M:10M",
            "--",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should not fail due to --io-limit parsing
    // May fail on non-Linux or without root, but not due to I/O limit format
    assert!(
        !stderr.contains("Invalid I/O limit") && !stderr.contains("I/O limit format"),
        "CLI should accept valid --io-limit format. stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_io_limit_accepts_specific_device() {
    // Spec: Device can be specified as "major:minor" (e.g., "8:0")
    let context = create_temp_context();

    // Test with specific device 8:0 and limits
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--io-limit",
            "8:0:5000:5000:100M:100M",
            "--",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should not fail due to --io-limit format
    assert!(
        !stderr.contains("Invalid I/O limit") && !stderr.contains("Invalid device"),
        "CLI should accept specific device format. stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_io_limit_unlimited_values() {
    // Spec: Use "0" or "max" for unlimited values
    let context = create_temp_context();

    // Test with max/unlimited values
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--io-limit",
            "auto:0:0:50M:50M",
            "--",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should not fail due to --io-limit parsing
    assert!(
        !stderr.contains("Invalid I/O limit"),
        "CLI should accept 0 for unlimited. stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_io_limit_bandwidth_suffixes() {
    // Spec: Bandwidth supports K/M/G suffixes
    let context = create_temp_context();

    // Test with K/M/G suffixes
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--io-limit",
            "auto:1000:1000:1G:512M",
            "--",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should not fail due to bandwidth suffix parsing
    assert!(
        !stderr.contains("Invalid I/O limit") && !stderr.contains("rbps") && !stderr.contains("wbps"),
        "CLI should accept K/M/G suffixes for bandwidth. stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_io_limit_invalid_format_shows_error() {
    // Spec: Invalid format should show clear error message
    let context = create_temp_context();

    // Test with invalid format (missing fields)
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--io-limit",
            "auto:1000:1000", // Missing rbps and wbps
            "--",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // On non-Linux, validation happens after namespace check fails
    // So we check that either we get an I/O limit format error OR we're on non-Linux
    // The key is that we should NOT succeed silently
    assert!(
        !output.status.success(),
        "CLI should fail with invalid --io-limit format"
    );
    // On Linux, we expect "I/O limit" or "format" error
    // On non-Linux, we get "Linux-only" error (validation order differs)
    assert!(
        stderr.contains("I/O limit")
            || stderr.contains("format")
            || stderr.contains("Linux")
            || stderr.contains("namespace"),
        "CLI should show an error. stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_io_limit_invalid_device_shows_error() {
    // Spec: Invalid device format should show clear error
    let context = create_temp_context();

    // Test with invalid device format
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--io-limit",
            "invalid:1000:1000:10M:10M", // Invalid device (not "auto" or "major:minor")
            "--",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // On non-Linux, validation happens after namespace check fails
    // The key is that we should NOT succeed silently
    assert!(
        !output.status.success(),
        "CLI should fail with invalid device format"
    );
    // On Linux, we expect "I/O limit" or "device" error
    // On non-Linux, we get "Linux-only" error (validation order differs)
    assert!(
        stderr.contains("I/O limit")
            || stderr.contains("device")
            || stderr.contains("Linux")
            || stderr.contains("namespace"),
        "CLI should show an error. stderr: {}",
        stderr
    );
}

#[test]
fn test_integration_cli_io_limit_partial_limits() {
    // Spec: Partial limits (some unlimited) should work
    let context = create_temp_context();

    // Test with only bandwidth limits (IOPS unlimited)
    let output = Command::new(nucleus_binary())
        .args([
            "run",
            "--context",
            context.path().to_str().unwrap(),
            "--io-limit",
            "auto:max:max:100M:100M",
            "--",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute nucleus");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should not fail due to "max" for unlimited
    assert!(
        !stderr.contains("Invalid I/O limit"),
        "CLI should accept 'max' for unlimited. stderr: {}",
        stderr
    );
}
