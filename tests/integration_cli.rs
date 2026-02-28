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
