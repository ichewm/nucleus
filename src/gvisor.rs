//! gVisor runtime integration for nucleus containers
//!
//! This module provides OCI-compliant bundle generation and runsc lifecycle
//! management for executing containers with gVisor's sandboxed runtime.
//!
//! ## OCI Bundle Structure
//! ```text
//! /tmp/nucleus-oci-<id>/
//! ├── config.json        # OCI runtime configuration
//! ├── rootfs/            # Container root filesystem
//! │   ├── bin/
//! │   ├── context/
//! │   ├── dev/
//! │   ├── etc/
//! │   ├── proc/
//! │   └── tmp/
//! └── ...
//! ```
//!
//! ## Lifecycle
//! 1. Create OCI bundle with config.json and rootfs
//! 2. `runsc create <container-id>` - Create container (stopped state)
//! 3. `runsc start <container-id>` - Start container execution
//! 4. `runsc wait <container-id>` - Wait for container to exit
//! 5. `runsc delete <container-id>` - Cleanup container state
//!
//! Note: gVisor operations require runsc to be installed and available on PATH.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, error, info, warn};

use crate::cli::RunArgs;
use crate::error::{NucleusError, Result};
use crate::filesystem::ContainerFilesystem;

/// OCI bundle manager
///
/// Handles creation and management of OCI-compliant bundles for gVisor.
pub struct OciBundle {
    /// Bundle directory path
    bundle_dir: PathBuf,

    /// Container ID
    container_id: String,

    /// Container filesystem (for cleanup reference)
    container_root: PathBuf,
}

impl OciBundle {
    /// Create a new OCI bundle for the given container
    ///
    /// # Arguments
    /// * `container_id` - Unique identifier for the container
    ///
    /// # Returns
    /// The OCI bundle manager
    pub fn new(container_id: &str) -> Self {
        let bundle_dir = std::env::temp_dir().join(format!("nucleus-oci-{}", container_id));
        let container_root = bundle_dir.join("rootfs");

        Self {
            bundle_dir,
            container_id: container_id.to_string(),
            container_root,
        }
    }

    /// Get the bundle directory path
    pub fn bundle_dir(&self) -> &Path {
        &self.bundle_dir
    }

    /// Get the rootfs path
    pub fn rootfs(&self) -> &Path {
        &self.container_root
    }

    /// Get the container ID
    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    /// Create the OCI bundle with config.json and rootfs
    ///
    /// # Arguments
    /// * `args` - CLI arguments for the container
    /// * `memory_bytes` - Memory limit in bytes
    ///
    /// # Returns
    /// The path to the bundle directory
    pub fn create(&self, args: &RunArgs, memory_bytes: u64) -> Result<PathBuf> {
        info!("Creating OCI bundle at {:?}", self.bundle_dir);

        // Create bundle directory
        fs::create_dir_all(&self.bundle_dir).map_err(|e| {
            NucleusError::GvisorExecute(format!("Failed to create bundle directory: {}", e))
        })?;

        // Create rootfs directory
        fs::create_dir_all(&self.container_root).map_err(|e| {
            NucleusError::GvisorExecute(format!("Failed to create rootfs directory: {}", e))
        })?;

        // Set up the container filesystem in rootfs
        let fs = ContainerFilesystem::new(self.container_root.clone(), memory_bytes);
        fs.setup(args)?;

        // Generate and write config.json
        let config_json = self.generate_config_json(args, memory_bytes);

        let config_path = self.bundle_dir.join("config.json");
        fs::write(&config_path, &config_json).map_err(|e| {
            NucleusError::GvisorExecute(format!("Failed to write config.json: {}", e))
        })?;

        info!("OCI bundle created successfully at {:?}", self.bundle_dir);
        debug!("config.json written to {:?}", config_path);

        Ok(self.bundle_dir.clone())
    }

    /// Generate OCI configuration JSON from CLI arguments
    fn generate_config_json(&self, args: &RunArgs, memory_bytes: u64) -> String {
        // Build OCI config as JSON
        // This follows the OCI runtime spec: https://github.com/opencontainers/runtime-spec
        let (executable, cmd_args) = args.command_parts();

        // Build command: [executable, ...args]
        let process_args: Vec<String> = std::iter::once(executable.to_string())
            .chain(cmd_args.iter().cloned())
            .collect();

        // Calculate CPU quota from cpus (e.g., 1.5 cores = 150000 us per 100000 us period)
        let cpu_period: u64 = 100000;
        let cpu_quota: i64 = (args.cpus * cpu_period as f64) as i64;

        // Build environment variables
        let env = vec![
            "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
            "TERM=xterm",
            "HOME=/root",
        ];

        // Build hostname
        let hostname = args.hostname.as_deref().unwrap_or("nucleus");

        // Generate JSON directly
        format!(r#"{{
  "ociVersion": "1.0.0",
  "process": {{
    "terminal": false,
    "user": {{
      "uid": 0,
      "gid": 0
    }},
    "args": {},
    "env": {},
    "cwd": "/",
    "capabilities": {{
      "bounding": [],
      "effective": [],
      "inheritable": [],
      "permitted": [],
      "ambient": []
    }},
    "noNewPrivileges": true
  }},
  "root": {{
    "path": "rootfs",
    "readonly": false
  }},
  "hostname": "{}",
  "linux": {{
    "namespaces": [
      {{"type": "pid"}},
      {{"type": "network"}},
      {{"type": "ipc"}},
      {{"type": "uts"}},
      {{"type": "mount"}}
    ],
    "resources": {{
      "memory": {{
        "limit": {},
        "swap": {}
      }},
      "cpu": {{
        "shares": 1024,
        "quota": {},
        "period": {}
      }}
    }}
  }}
}}"#,
            to_json_array(&process_args),
            to_json_array(&env),
            hostname,
            memory_bytes,
            memory_bytes,
            cpu_quota,
            cpu_period
        )
    }

    /// Clean up the OCI bundle directory
    pub fn cleanup(&self) -> Result<()> {
        info!("Cleaning up OCI bundle at {:?}", self.bundle_dir);

        if self.bundle_dir.exists() {
            fs::remove_dir_all(&self.bundle_dir).map_err(|e| {
                NucleusError::GvisorExecute(format!("Failed to cleanup bundle directory: {}", e))
            })?;
            debug!("Bundle directory removed");
        }

        Ok(())
    }
}

impl Drop for OciBundle {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        if self.bundle_dir.exists() {
            let _ = fs::remove_dir_all(&self.bundle_dir);
        }
    }
}

/// Convert a slice of strings to a JSON array string
fn to_json_array(items: &[impl AsRef<str>]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|s| format!("\"{}\"", escape_json_string(s.as_ref())))
        .collect();
    format!("[{}]", quoted.join(", "))
}

/// Escape special characters for JSON strings
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// gVisor runtime executor
///
/// Manages the runsc lifecycle: create → start → wait → delete
pub struct GvisorExecutor {
    /// Container ID
    container_id: String,

    /// OCI bundle
    bundle: OciBundle,
}

impl GvisorExecutor {
    /// Create a new gVisor executor
    ///
    /// # Arguments
    /// * `container_id` - Unique container identifier
    pub fn new(container_id: &str) -> Self {
        Self {
            container_id: container_id.to_string(),
            bundle: OciBundle::new(container_id),
        }
    }

    /// Run a container with gVisor
    ///
    /// This executes the full lifecycle:
    /// 1. Create OCI bundle
    /// 2. runsc create
    /// 3. runsc start
    /// 4. runsc wait
    /// 5. runsc delete (cleanup)
    ///
    /// # Arguments
    /// * `args` - CLI arguments
    /// * `memory_bytes` - Memory limit in bytes
    ///
    /// # Returns
    /// Exit code of the container process
    pub fn run(&self, args: &RunArgs, memory_bytes: u64) -> Result<i32> {
        info!("Starting gVisor execution for container {}", self.container_id);

        // Step 1: Create OCI bundle
        self.bundle.create(args, memory_bytes)?;

        // Step 2: Create container with runsc
        self.runsc_create()?;

        // Ensure cleanup on error
        let result = self.execute_lifecycle();

        // Step 5: Always delete container (cleanup)
        if let Err(e) = self.runsc_delete() {
            warn!("Failed to delete container: {}", e);
        }

        // Step 6: Cleanup bundle directory
        if let Err(e) = self.bundle.cleanup() {
            warn!("Failed to cleanup bundle: {}", e);
        }

        result
    }

    /// Execute the lifecycle: start → wait
    fn execute_lifecycle(&self) -> Result<i32> {
        // Step 3: Start the container
        self.runsc_start()?;

        // Step 4: Wait for container to complete
        let exit_code = self.runsc_wait()?;

        info!("Container {} exited with code {}", self.container_id, exit_code);
        Ok(exit_code)
    }

    /// Execute `runsc create` to create the container
    fn runsc_create(&self) -> Result<()> {
        info!("Creating container with runsc: {}", self.container_id);

        let output = self.runsc_command()
            .arg("create")
            .arg("--bundle")
            .arg(self.bundle.bundle_dir())
            .arg(&self.container_id)
            .output()
            .map_err(|e| {
                NucleusError::GvisorExecute(format!("Failed to execute runsc create: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("runsc create failed: {}", stderr);
            return Err(NucleusError::GvisorExecute(format!(
                "runsc create failed: {}",
                stderr
            )));
        }

        debug!("Container created successfully");
        Ok(())
    }

    /// Execute `runsc start` to start the container
    fn runsc_start(&self) -> Result<()> {
        info!("Starting container with runsc: {}", self.container_id);

        let output = self.runsc_command()
            .arg("start")
            .arg(&self.container_id)
            .output()
            .map_err(|e| {
                NucleusError::GvisorExecute(format!("Failed to execute runsc start: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("runsc start failed: {}", stderr);
            return Err(NucleusError::GvisorExecute(format!(
                "runsc start failed: {}",
                stderr
            )));
        }

        debug!("Container started successfully");
        Ok(())
    }

    /// Execute `runsc wait` to wait for container completion
    fn runsc_wait(&self) -> Result<i32> {
        info!("Waiting for container to complete: {}", self.container_id);

        let status = self.runsc_command()
            .arg("wait")
            .arg(&self.container_id)
            .status()
            .map_err(|e| {
                NucleusError::GvisorExecute(format!("Failed to execute runsc wait: {}", e))
            })?;

        let exit_code = status.code().unwrap_or(1);
        debug!("runsc wait completed with exit code: {}", exit_code);

        Ok(exit_code)
    }

    /// Execute `runsc delete` to cleanup container state
    fn runsc_delete(&self) -> Result<()> {
        info!("Deleting container with runsc: {}", self.container_id);

        let output = self.runsc_command()
            .arg("delete")
            .arg("--force")
            .arg(&self.container_id)
            .output()
            .map_err(|e| {
                NucleusError::GvisorExecute(format!("Failed to execute runsc delete: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("runsc delete failed (non-fatal): {}", stderr);
        } else {
            debug!("Container deleted successfully");
        }

        Ok(())
    }

    /// Create a runsc Command with common setup
    fn runsc_command(&self) -> Command {
        let mut cmd = Command::new("runsc");

        // Use ptrace platform (default, works without KVM)
        cmd.arg("--platform").arg("ptrace");

        // Set root directory for container state
        let runsc_root = std::env::temp_dir().join("nucleus-runsc");
        cmd.arg("--root").arg(&runsc_root);

        // Debug logging for runsc (can be controlled via env var)
        if std::env::var("NUCLEUS_GVISOR_DEBUG").is_ok() {
            cmd.arg("--debug").arg("--log-format").arg("text");
        }

        cmd
    }
}

/// Check if gVisor (runsc) is available on the system
pub fn is_gvisor_available() -> bool {
    which::which("runsc").is_ok()
}

/// Get the path to the runsc binary
pub fn find_runsc() -> Result<PathBuf> {
    which::which("runsc").map_err(|_| {
        NucleusError::GvisorNotFound(
            "runsc not found in PATH. Install gVisor from https://gvisor.dev/docs/user_guide/install/".to_string()
        )
    })
}

/// Run a container with gVisor
///
/// This is the main entry point for gVisor execution.
///
/// # Arguments
/// * `container_id` - Unique container identifier
/// * `args` - CLI arguments
/// * `memory_bytes` - Memory limit in bytes
///
/// # Returns
/// Exit code of the container process
pub fn run_with_gvisor(container_id: &str, args: &RunArgs, memory_bytes: u64) -> Result<i32> {
    // Verify gVisor is available
    find_runsc()?;

    let executor = GvisorExecutor::new(container_id);
    executor.run(args, memory_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_oci_bundle_new() {
        let bundle = OciBundle::new("test123");

        assert!(bundle.bundle_dir().to_str().unwrap().contains("test123"));
        assert!(bundle.rootfs().to_str().unwrap().contains("rootfs"));
        assert_eq!(bundle.container_id(), "test123");
    }

    #[test]
    fn test_gvisor_executor_new() {
        let executor = GvisorExecutor::new("test456");

        assert_eq!(executor.container_id, "test456");
    }

    #[test]
    fn test_is_gvisor_available() {
        // This test just checks the function runs without error
        // The actual result depends on whether runsc is installed
        let _ = is_gvisor_available();
    }

    #[test]
    fn test_find_runsc() {
        // This test just checks the function runs
        // The actual result depends on whether runsc is installed
        let result = find_runsc();
        if is_gvisor_available() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_oci_bundle_cleanup_removes_directory() {
        let temp = TempDir::new().unwrap();
        let bundle_dir = temp.path().join("test-bundle");

        // Create a bundle manually
        fs::create_dir_all(bundle_dir.join("rootfs")).unwrap();
        fs::write(bundle_dir.join("config.json"), "{}").unwrap();

        // Create OciBundle that points to our test directory
        let mut bundle = OciBundle::new("test-bundle");
        bundle.bundle_dir = bundle_dir.clone();
        bundle.container_root = bundle_dir.join("rootfs");

        // Cleanup should remove the directory
        bundle.cleanup().unwrap();
        assert!(!bundle_dir.exists());
    }

    #[test]
    fn test_escape_json_string() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json_string("hello\\world"), "hello\\\\world");
        assert_eq!(escape_json_string("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_json_string("hello\tworld"), "hello\\tworld");
    }

    #[test]
    fn test_to_json_array() {
        let arr = vec!["a", "b", "c"];
        let json = to_json_array(&arr);
        assert_eq!(json, "[\"a\", \"b\", \"c\"]");

        let empty: Vec<&str> = vec![];
        let json = to_json_array(&empty);
        assert_eq!(json, "[]");
    }

    #[test]
    fn test_to_json_array_escapes() {
        let arr = vec!["hello\"world", "test"];
        let json = to_json_array(&arr);
        assert_eq!(json, "[\"hello\\\"world\", \"test\"]");
    }

    #[test]
    fn test_generate_config_json_structure() {
        let bundle = OciBundle::new("test");

        // Create a minimal RunArgs
        let args = RunArgs {
            context: std::path::PathBuf::from("/tmp"),
            memory: "512M".to_string(),
            cpus: 1.0,
            runtime: "gvisor".to_string(),
            hostname: Some("testhost".to_string()),
            io_limit: None,
            command: vec!["/bin/echo".to_string(), "hello".to_string()],
        };

        let json = bundle.generate_config_json(&args, 512 * 1024 * 1024);

        // Verify key fields are present
        assert!(json.contains("\"ociVersion\": \"1.0.0\""));
        assert!(json.contains("\"hostname\": \"testhost\""));
        assert!(json.contains("\"/bin/echo\""));
        assert!(json.contains("\"hello\""));
        assert!(json.contains("\"type\": \"pid\""));
        assert!(json.contains("\"type\": \"mount\""));
        assert!(json.contains("\"limit\": 536870912"));
    }
}
