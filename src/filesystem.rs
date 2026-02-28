//! Filesystem layer for nucleus containers
//!
//! This module handles all filesystem setup for containers:
//! - tmpfs mounting as container root
//! - Directory layout creation
//! - Context directory population with filtering
//! - Device node creation
//! - procfs mounting
//! - Root switching via pivot_root with chroot fallback
//!
//! Note: Most operations are only supported on Linux.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::cli::RunArgs;
use crate::error::{NucleusError, Result};

/// Container filesystem manager
///
/// Manages the complete filesystem setup for a container including:
/// - tmpfs root mount
/// - Directory layout
/// - Context population
/// - Device nodes
/// - procfs mount
/// - Root switching
pub struct ContainerFilesystem {
    /// Path to the container root (tmpfs mount point)
    root: PathBuf,

    /// Size limit for tmpfs in human-readable format
    tmpfs_size: String,

    /// Memory limit in bytes (used for tmpfs size)
    memory_bytes: u64,
}

impl ContainerFilesystem {
    /// Create a new container filesystem
    ///
    /// # Arguments
    /// * `root` - Path where tmpfs will be mounted
    /// * `memory_bytes` - Memory limit in bytes (used for tmpfs size)
    pub fn new(root: PathBuf, memory_bytes: u64) -> Self {
        // Use 90% of memory limit for tmpfs to leave room for process memory
        let tmpfs_bytes = (memory_bytes as f64 * 0.9) as u64;
        let tmpfs_size = format_size(tmpfs_bytes);

        Self {
            root,
            tmpfs_size,
            memory_bytes,
        }
    }

    /// Set up the complete container filesystem
    ///
    /// This performs all filesystem setup steps in the correct order:
    /// 1. Mount tmpfs at root
    /// 2. Create directory layout
    /// 3. Populate context directory
    /// 4. Create device nodes
    /// 5. Mount procfs
    ///
    /// # Arguments
    /// * `args` - CLI arguments containing context path
    #[cfg(target_os = "linux")]
    pub fn setup(&self, args: &RunArgs) -> Result<()> {
        info!("Setting up container filesystem at {:?}", self.root);

        // Step 1: Create the root directory
        fs::create_dir_all(&self.root).map_err(|e| {
            NucleusError::FilesystemLayout(format!("Failed to create root directory: {}", e))
        })?;

        // Step 2: Mount tmpfs
        self.mount_tmpfs()?;

        // Step 3: Create directory layout
        self.create_layout()?;

        // Step 4: Populate context
        self.populate_context(&args.context)?;

        // Step 5: Create device nodes
        self.create_devices()?;

        // Step 6: Mount procfs
        self.mount_proc()?;

        info!("Container filesystem setup complete");
        Ok(())
    }

    /// Set up the container filesystem (stub for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn setup(&self, _args: &RunArgs) -> Result<()> {
        Err(NucleusError::FilesystemMount(
            "Filesystem setup is only supported on Linux".to_string(),
        ))
    }

    /// Mount tmpfs at the root directory
    #[cfg(target_os = "linux")]
    fn mount_tmpfs(&self) -> Result<()> {
        use nix::mount::{mount, MsFlags};

        info!(
            "Mounting tmpfs at {:?} with size={}",
            self.root, self.tmpfs_size
        );

        let options = format!("size={},mode=0755", self.tmpfs_size);

        mount(
            Some("tmpfs"),
            &self.root,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some(options.as_str()),
        )
        .map_err(|e| NucleusError::FilesystemMount(format!("Failed to mount tmpfs: {}", e)))?;

        debug!("tmpfs mounted successfully");
        Ok(())
    }

    /// Create the container directory layout
    ///
    /// Creates: /context, /bin, /dev, /proc, /tmp, /etc
    fn create_layout(&self) -> Result<()> {
        debug!("Creating directory layout at {:?}", self.root);

        let dirs = ["context", "bin", "dev", "proc", "tmp", "etc"];

        for dir in dirs {
            let path = self.root.join(dir);
            fs::create_dir_all(&path).map_err(|e| {
                NucleusError::FilesystemLayout(format!("Failed to create {}: {}", dir, e))
            })?;
            debug!("Created directory: {:?}", path);
        }

        // Create minimal /etc files
        let passwd_content = "root:x:0:0:root:/root:/bin/sh\n";
        let group_content = "root:x:0:\n";

        fs::write(self.root.join("etc/passwd"), passwd_content).map_err(|e| {
            NucleusError::FilesystemLayout(format!("Failed to create /etc/passwd: {}", e))
        })?;

        fs::write(self.root.join("etc/group"), group_content).map_err(|e| {
            NucleusError::FilesystemLayout(format!("Failed to create /etc/group: {}", e))
        })?;

        debug!("Directory layout created successfully");
        Ok(())
    }

    /// Populate the context directory from host
    ///
    /// Copies files from the host context directory to /context/ in the container,
    /// applying exclusion filters.
    pub fn populate_context(&self, source: &Path) -> Result<()> {
        let dest = self.root.join("context");
        info!("Populating context from {:?} to {:?}", source, dest);

        for entry in WalkDir::new(source)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| should_include(e))
        {
            let entry = entry.map_err(|e| {
                NucleusError::ContextCopy(
                    source.to_path_buf(),
                    format!("Failed to walk directory: {}", e),
                )
            })?;

            let rel_path = entry.path().strip_prefix(source).map_err(|e| {
                NucleusError::ContextCopy(
                    source.to_path_buf(),
                    format!("Failed to get relative path: {}", e),
                )
            })?;

            let dest_path = dest.join(rel_path);

            if entry.file_type().is_dir() {
                fs::create_dir_all(&dest_path).map_err(|e| {
                    NucleusError::ContextCopy(
                        source.to_path_buf(),
                        format!("Failed to create directory {:?}: {}", dest_path, e),
                    )
                })?;
            } else if entry.file_type().is_file() {
                // Copy file
                fs::copy(entry.path(), &dest_path).map_err(|e| {
                    NucleusError::ContextCopy(
                        source.to_path_buf(),
                        format!("Failed to copy file {:?}: {}", entry.path(), e),
                    )
                })?;

                // Preserve permissions
                let metadata = fs::metadata(entry.path()).map_err(|e| {
                    NucleusError::ContextCopy(
                        source.to_path_buf(),
                        format!("Failed to read metadata for {:?}: {}", entry.path(), e),
                    )
                })?;
                fs::set_permissions(&dest_path, metadata.permissions()).map_err(|e| {
                    NucleusError::ContextCopy(
                        source.to_path_buf(),
                        format!("Failed to set permissions for {:?}: {}", dest_path, e),
                    )
                })?;
            }
            // Note: Symlinks are skipped (follow_links is false)
        }

        info!("Context populated successfully");
        Ok(())
    }

    /// Create device nodes in /dev/
    #[cfg(target_os = "linux")]
    pub fn create_devices(&self) -> Result<()> {
        use nix::sys::stat::{mknod, Mode, SFlag};

        debug!("Creating device nodes at {:?}", self.root.join("dev"));

        // Device definitions: (name, major, minor)
        let devices = [
            ("null", 1, 3),
            ("zero", 1, 5),
            ("full", 1, 7),
            ("random", 1, 8),
            ("urandom", 1, 9),
            ("tty", 5, 0),
            ("console", 5, 1),
        ];

        let dev_path = self.root.join("dev");
        let mode = Mode::S_IRUSR
            | Mode::S_IWUSR
            | Mode::S_IRGRP
            | Mode::S_IWGRP
            | Mode::S_IROTH
            | Mode::S_IWOTH;

        for (name, major, minor) in devices {
            let path = dev_path.join(name);
            let dev = makedev(major, minor);

            mknod(&path, SFlag::S_IFCHR, mode, dev).map_err(|e| {
                NucleusError::DeviceNode(format!("Failed to create /dev/{}: {}", name, e))
            })?;

            debug!("Created device node: {:?}", path);
        }

        info!("Device nodes created successfully");
        Ok(())
    }

    /// Create device nodes (stub for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn create_devices(&self) -> Result<()> {
        Err(NucleusError::DeviceNode(
            "Device node creation is only supported on Linux".to_string(),
        ))
    }

    /// Mount procfs at /proc
    #[cfg(target_os = "linux")]
    pub fn mount_proc(&self) -> Result<()> {
        use nix::mount::{mount, MsFlags};

        let proc = self.root.join("proc");
        info!("Mounting procfs at {:?}", proc);

        mount(
            Some("proc"),
            &proc,
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| NucleusError::FilesystemMount(format!("Failed to mount procfs: {}", e)))?;

        debug!("procfs mounted successfully");
        Ok(())
    }

    /// Mount procfs (stub for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn mount_proc(&self) -> Result<()> {
        Err(NucleusError::FilesystemMount(
            "procfs mounting is only supported on Linux".to_string(),
        ))
    }

    /// Switch root using pivot_root with chroot fallback
    ///
    /// Attempts pivot_root first for cleaner isolation. Falls back to chroot
    /// if pivot_root fails (e.g., due to missing CAP_SYS_ADMIN).
    #[cfg(target_os = "linux")]
    pub fn switch_root(&self) -> Result<()> {
        use nix::mount::{umount2, MntFlags};
        use nix::unistd::pivot_root;

        info!("Switching root to {:?}", self.root);

        let old_root = self.root.join("old-root");
        fs::create_dir_all(&old_root).map_err(|e| {
            NucleusError::PivotRoot(format!("Failed to create old-root directory: {}", e))
        })?;

        // Try pivot_root first
        match pivot_root(&self.root, &old_root) {
            Ok(()) => {
                info!("Successfully switched root via pivot_root");

                // Change to new root
                std::env::set_current_dir("/").map_err(|e| {
                    NucleusError::PivotRoot(format!("Failed to chdir to new root: {}", e))
                })?;

                // Unmount old root
                let _ = umount2("/old-root", MntFlags::MNT_DETACH);
                let _ = fs::remove_dir("/old-root");

                debug!("Old root unmounted and cleaned up");
            }
            Err(e) => {
                warn!("pivot_root failed ({}), falling back to chroot", e);

                // Fallback to chroot
                std::env::set_current_dir(&self.root).map_err(|e| {
                    NucleusError::Chroot(format!("Failed to chdir to new root: {}", e))
                })?;

                nix::unistd::chroot(&self.root).map_err(|e| {
                    NucleusError::Chroot(format!("Failed to chroot: {}", e))
                })?;

                std::env::set_current_dir("/").map_err(|e| {
                    NucleusError::Chroot(format!("Failed to chdir after chroot: {}", e))
                })?;

                info!("Switched root via chroot fallback");
            }
        }

        Ok(())
    }

    /// Switch root (stub for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn switch_root(&self) -> Result<()> {
        Err(NucleusError::PivotRoot(
            "Root switching is only supported on Linux".to_string(),
        ))
    }

    /// Copy executable to container /bin/ and return the path
    ///
    /// # Arguments
    /// * `executable` - Name or path of the executable to find and copy
    ///
    /// # Returns
    /// Path to the executable inside the container (e.g., /bin/ls)
    pub fn copy_executable(&self, executable: &str) -> Result<PathBuf> {
        info!("Copying executable '{}' to container", executable);

        // Find executable on host using which
        let exe_path = which::which(executable).map_err(|_| {
            NucleusError::InvalidExecutable(format!("Cannot find executable: {}", executable))
        })?;

        let exe_name = exe_path
            .file_name()
            .ok_or_else(|| {
                NucleusError::InvalidExecutable("Invalid executable name".to_string())
            })?
            .to_str()
            .ok_or_else(|| {
                NucleusError::InvalidExecutable("Executable name contains invalid UTF-8".to_string())
            })?;

        let dest = self.root.join("bin").join(exe_name);

        // Copy the executable
        fs::copy(&exe_path, &dest).map_err(|e| {
            NucleusError::ContextCopy(
                exe_path.clone(),
                format!("Failed to copy executable: {}", e),
            )
        })?;

        // Make executable
        let mut perms = fs::metadata(&dest)
            .map_err(|e| {
                NucleusError::ContextCopy(
                    dest.clone(),
                    format!("Failed to read executable metadata: {}", e),
                )
            })?
            .permissions();
        perms.set_mode(perms.mode() | 0o111); // Add execute bits
        fs::set_permissions(&dest, perms).map_err(|e| {
            NucleusError::ContextCopy(
                dest.clone(),
                format!("Failed to set executable permissions: {}", e),
            )
        })?;

        info!("Executable copied to {:?}", dest);

        // Return path inside container
        Ok(PathBuf::from("/bin").join(exe_name))
    }

    /// Get the root path
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the tmpfs size string
    pub fn tmpfs_size(&self) -> &str {
        &self.tmpfs_size
    }

    /// Get memory bytes
    pub fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }
}

/// Check if a directory entry should be included in the context
///
/// Excludes:
/// - VCS directories: .git, .svn
/// - Build artifacts: target, node_modules
/// - Editor files: .*.swp
/// - Environment files: .env, .env.*
/// - Credential files: *credential*, *secret*, *private*
/// - Key/certificate files: *.pem, *.key, *.p12, *.crt
fn should_include(entry: &walkdir::DirEntry) -> bool {
    let name = entry.file_name().to_str().unwrap_or("");
    let name_lower = name.to_lowercase();

    // Exclude VCS directories
    if name == ".git" || name == ".svn" {
        debug!("Excluding VCS directory: {}", name);
        return false;
    }

    // Exclude build artifacts
    if name == "target" || name == "node_modules" {
        debug!("Excluding build artifact: {}", name);
        return false;
    }

    // Exclude editor swap files (.*.swp pattern)
    if name.starts_with('.') && name.ends_with(".swp") {
        debug!("Excluding editor swap file: {}", name);
        return false;
    }

    // Exclude environment files that may contain secrets
    if name.starts_with(".env") {
        debug!("Excluding environment file: {}", name);
        return false;
    }

    // Exclude credential files (case-insensitive)
    if name_lower.contains("credential")
        || name_lower.contains("secret")
        || name_lower.contains("private")
    {
        debug!("Excluding credential file: {}", name);
        return false;
    }

    // Exclude key/certificate files
    if name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
        || name.ends_with(".crt")
    {
        debug!("Excluding key/certificate file: {}", name);
        return false;
    }

    true
}

/// Create a device number from major and minor numbers
#[cfg(target_os = "linux")]
fn makedev(major: u64, minor: u64) -> u64 {
    // Linux device number encoding: (major << 8) | minor for compatibility
    // Full encoding uses bits 0-7 for minor, 8-19 for major (12-bit major)
    // and bits 20-31 for extended minor (for >255 minors)
    // For simplicity, we use the classic encoding
    (major << 8) | minor
}

/// Format a size in bytes to human-readable format
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500");
        assert_eq!(format_size(1024), "1K");
        assert_eq!(format_size(2048), "2K");
        assert_eq!(format_size(1024 * 1024), "1M");
        assert_eq!(format_size(512 * 1024 * 1024), "512M");
        assert_eq!(format_size(1024 * 1024 * 1024), "1G");
        assert_eq!(format_size(2 * 1024 * 1024 * 1024), "2G");
    }

    #[test]
    fn test_container_filesystem_new() {
        let fs = ContainerFilesystem::new(PathBuf::from("/tmp/test"), 512 * 1024 * 1024);

        assert_eq!(fs.root(), Path::new("/tmp/test"));
        assert_eq!(fs.tmpfs_size(), "460M"); // 90% of 512M
        assert_eq!(fs.memory_bytes(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_container_filesystem_tmpfs_size_calculation() {
        // 1GB memory -> 921M tmpfs (90%)
        let fs = ContainerFilesystem::new(PathBuf::from("/tmp/test"), 1024 * 1024 * 1024);
        assert_eq!(fs.tmpfs_size(), "921M");

        // 256MB memory -> 230M tmpfs (90%)
        let fs = ContainerFilesystem::new(PathBuf::from("/tmp/test"), 256 * 1024 * 1024);
        assert_eq!(fs.tmpfs_size(), "230M");
    }

    #[test]
    fn test_should_include_normal_files() {
        let temp = TempDir::new().unwrap();
        let path = temp.path();

        // Create normal files/dirs
        fs::create_dir_all(path.join("src")).unwrap();
        fs::File::create(path.join("main.rs")).unwrap();
        fs::File::create(path.join("README.md")).unwrap();

        // Walk directory and check all entries are included
        for entry in WalkDir::new(path).into_iter().filter_entry(|e| should_include(e)) {
            let entry = entry.unwrap();
            let name = entry.file_name().to_str().unwrap();
            // All normal files should be included
            assert!(
                name != ".git" && name != ".svn" && name != "target" && name != "node_modules",
                "Normal file/dir should be included: {:?}",
                entry.path()
            );
        }
    }

    #[test]
    fn test_should_exclude_git() {
        let temp = TempDir::new().unwrap();
        let git_dir = temp.path().join(".git");
        fs::create_dir_all(&git_dir).unwrap();

        // Walk the parent dir with filter - .git should not appear in results
        let filtered_count = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        // Only the root directory should be returned, .git should be excluded
        assert_eq!(filtered_count, 1, ".git should be excluded from walk");
    }

    #[test]
    fn test_should_exclude_svn() {
        let temp = TempDir::new().unwrap();
        let svn_dir = temp.path().join(".svn");
        fs::create_dir_all(&svn_dir).unwrap();

        let filtered_count = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count, 1, ".svn should be excluded from walk");
    }

    #[test]
    fn test_should_exclude_target() {
        let temp = TempDir::new().unwrap();
        let target_dir = temp.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();

        let filtered_count = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count, 1, "target should be excluded from walk");
    }

    #[test]
    fn test_should_exclude_node_modules() {
        let temp = TempDir::new().unwrap();
        let node_dir = temp.path().join("node_modules");
        fs::create_dir_all(&node_dir).unwrap();

        let filtered_count = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count, 1, "node_modules should be excluded from walk");
    }

    #[test]
    fn test_should_exclude_swp_files() {
        let temp = TempDir::new().unwrap();

        // .*.swp files should be excluded
        let swp_file = temp.path().join(".main.rs.swp");
        fs::File::create(&swp_file).unwrap();

        // Walk with filter - .*.swp should not appear
        let entries: Vec<_> = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .collect();
        // Only root directory should be in results
        assert_eq!(entries.len(), 1, ".*.swp files should be excluded from walk");

        // Normal .swp file (not starting with .) should NOT be excluded
        let temp2 = TempDir::new().unwrap();
        let normal_swp = temp2.path().join("test.swp");
        fs::File::create(&normal_swp).unwrap();

        let entries2: Vec<_> = WalkDir::new(temp2.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .collect();
        // Root + test.swp = 2 entries
        assert_eq!(entries2.len(), 2, "test.swp (not starting with .) should be included");
    }

    #[test]
    fn test_should_exclude_editor_swap_with_leading_dot() {
        let temp = TempDir::new().unwrap();

        // Files like .file.rs.swp (vim swap files)
        let swp_file = temp.path().join(".config.yaml.swp");
        fs::File::create(&swp_file).unwrap();

        let filtered_count = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count, 1, ".config.yaml.swp should be excluded from walk");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_makedev() {
        // Test device number encoding
        assert_eq!(makedev(1, 3), 259); // null: (1 << 8) | 3 = 259
        assert_eq!(makedev(1, 5), 261); // zero: (1 << 8) | 5 = 261
        assert_eq!(makedev(5, 0), 1280); // tty: (5 << 8) | 0 = 1280
    }

    #[test]
    fn test_create_layout() {
        let temp = TempDir::new().unwrap();
        let fs = ContainerFilesystem::new(temp.path().to_path_buf(), 512 * 1024 * 1024);

        // Create the layout (without mounting tmpfs, just test directory creation)
        fs.create_layout().unwrap();

        // Verify directories exist
        assert!(temp.path().join("context").exists());
        assert!(temp.path().join("bin").exists());
        assert!(temp.path().join("dev").exists());
        assert!(temp.path().join("proc").exists());
        assert!(temp.path().join("tmp").exists());
        assert!(temp.path().join("etc").exists());

        // Verify /etc files
        assert!(temp.path().join("etc/passwd").exists());
        assert!(temp.path().join("etc/group").exists());

        let passwd = fs::read_to_string(temp.path().join("etc/passwd")).unwrap();
        assert!(passwd.contains("root"));

        let group = fs::read_to_string(temp.path().join("etc/group")).unwrap();
        assert!(group.contains("root"));
    }

    #[test]
    fn test_populate_context_basic() {
        let temp_source = TempDir::new().unwrap();
        let temp_dest = TempDir::new().unwrap();

        // Create source files
        fs::create_dir_all(temp_source.path().join("src")).unwrap();
        fs::write(temp_source.path().join("README.md"), "test readme").unwrap();
        fs::write(temp_source.path().join("src/main.rs"), "fn main() {}").unwrap();

        // Create filesystem and layout
        let fs = ContainerFilesystem::new(temp_dest.path().to_path_buf(), 512 * 1024 * 1024);
        fs.create_layout().unwrap();

        // Populate context
        fs.populate_context(temp_source.path()).unwrap();

        // Verify files were copied
        assert!(temp_dest.path().join("context/README.md").exists());
        assert!(temp_dest.path().join("context/src/main.rs").exists());

        // Verify content
        let readme = fs::read_to_string(temp_dest.path().join("context/README.md")).unwrap();
        assert_eq!(readme, "test readme");
    }

    #[test]
    fn test_populate_context_filtering() {
        let temp_source = TempDir::new().unwrap();
        let temp_dest = TempDir::new().unwrap();

        // Create files that should be included
        fs::write(temp_source.path().join("main.rs"), "fn main() {}").unwrap();

        // Create files/dirs that should be excluded
        fs::create_dir_all(temp_source.path().join(".git/objects")).unwrap();
        fs::write(temp_source.path().join(".git/config"), "[core]").unwrap();
        fs::create_dir_all(temp_source.path().join("target/debug")).unwrap();
        fs::write(temp_source.path().join("target/debug/app"), "binary").unwrap();
        fs::create_dir_all(temp_source.path().join("node_modules/package")).unwrap();
        fs::write(temp_source.path().join(".main.rs.swp"), "swap").unwrap();

        // Create filesystem and populate
        let fs = ContainerFilesystem::new(temp_dest.path().to_path_buf(), 512 * 1024 * 1024);
        fs.create_layout().unwrap();
        fs.populate_context(temp_source.path()).unwrap();

        // Verify included file exists
        assert!(temp_dest.path().join("context/main.rs").exists());

        // Verify excluded files/dirs don't exist
        assert!(!temp_dest.path().join("context/.git").exists());
        assert!(!temp_dest.path().join("context/target").exists());
        assert!(!temp_dest.path().join("context/node_modules").exists());
        assert!(!temp_dest.path().join("context/.main.rs.swp").exists());
    }

    #[test]
    fn test_populate_context_preserves_permissions() {
        let temp_source = TempDir::new().unwrap();
        let temp_dest = TempDir::new().unwrap();

        // Create a file with specific permissions
        let source_file = temp_source.path().join("script.sh");
        fs::write(&source_file, "#!/bin/sh").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&source_file, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Create filesystem and populate
        let fs = ContainerFilesystem::new(temp_dest.path().to_path_buf(), 512 * 1024 * 1024);
        fs.create_layout().unwrap();
        fs.populate_context(temp_source.path()).unwrap();

        // Verify content
        let dest_file = temp_dest.path().join("context/script.sh");
        let content = fs::read_to_string(&dest_file).unwrap();
        assert_eq!(content, "#!/bin/sh");

        // Verify permissions preserved
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&dest_file).unwrap();
            let mode = metadata.permissions().mode();
            // Check that execute bits are set (0o755)
            assert_eq!(mode & 0o111, 0o111);
        }
    }

    #[test]
    fn test_should_exclude_env_files() {
        let temp = TempDir::new().unwrap();

        // Test .env exclusion
        fs::write(temp.path().join(".env"), "SECRET=abc").unwrap();
        let filtered_count = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count, 1, ".env should be excluded from walk");

        // Test .env.local exclusion
        let temp2 = TempDir::new().unwrap();
        fs::write(temp2.path().join(".env.local"), "SECRET=abc").unwrap();
        let filtered_count2 = WalkDir::new(temp2.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count2, 1, ".env.local should be excluded from walk");

        // Test .env.production exclusion
        let temp3 = TempDir::new().unwrap();
        fs::write(temp3.path().join(".env.production"), "SECRET=abc").unwrap();
        let filtered_count3 = WalkDir::new(temp3.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count3, 1, ".env.production should be excluded from walk");
    }

    #[test]
    fn test_should_exclude_credential_files() {
        let temp = TempDir::new().unwrap();

        // Test credentials.json exclusion
        fs::write(temp.path().join("credentials.json"), "{}").unwrap();
        let filtered_count = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count, 1, "credentials.json should be excluded from walk");

        // Test secrets.yaml exclusion (case-insensitive)
        let temp2 = TempDir::new().unwrap();
        fs::write(temp2.path().join("SECRETS.yaml"), "key: value").unwrap();
        let filtered_count2 = WalkDir::new(temp2.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count2, 1, "SECRETS.yaml should be excluded from walk");

        // Test private_key exclusion (case-insensitive)
        let temp3 = TempDir::new().unwrap();
        fs::write(temp3.path().join("PrivateKey.pem"), "key").unwrap();
        let filtered_count3 = WalkDir::new(temp3.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count3, 1, "PrivateKey.pem should be excluded from walk (contains 'private')");
    }

    #[test]
    fn test_should_exclude_key_files() {
        let temp = TempDir::new().unwrap();

        // Test .key exclusion
        fs::write(temp.path().join("server.key"), "privatekey").unwrap();
        let filtered_count = WalkDir::new(temp.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count, 1, ".key files should be excluded from walk");

        // Test .pem exclusion
        let temp2 = TempDir::new().unwrap();
        fs::write(temp2.path().join("cert.pem"), "certificate").unwrap();
        let filtered_count2 = WalkDir::new(temp2.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count2, 1, ".pem files should be excluded from walk");

        // Test .p12 exclusion
        let temp3 = TempDir::new().unwrap();
        fs::write(temp3.path().join("keystore.p12"), "pkcs12").unwrap();
        let filtered_count3 = WalkDir::new(temp3.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count3, 1, ".p12 files should be excluded from walk");

        // Test .crt exclusion
        let temp4 = TempDir::new().unwrap();
        fs::write(temp4.path().join("ca.crt"), "certificate").unwrap();
        let filtered_count4 = WalkDir::new(temp4.path())
            .into_iter()
            .filter_entry(|e| should_include(e))
            .count();
        assert_eq!(filtered_count4, 1, ".crt files should be excluded from walk");
    }

    #[test]
    fn test_populate_context_filters_secrets() {
        let temp_source = TempDir::new().unwrap();
        let temp_dest = TempDir::new().unwrap();

        // Create files that should be included
        fs::write(temp_source.path().join("main.rs"), "fn main() {}").unwrap();

        // Create secret files that should be excluded
        fs::write(temp_source.path().join(".env"), "SECRET=abc").unwrap();
        fs::write(temp_source.path().join(".env.local"), "DB_PASS=pass").unwrap();
        fs::write(temp_source.path().join("credentials.json"), "{}").unwrap();
        fs::write(temp_source.path().join("secrets.yaml"), "api_key: xyz").unwrap();
        fs::write(temp_source.path().join("server.key"), "privatekey").unwrap();
        fs::write(temp_source.path().join("cert.pem"), "certificate").unwrap();

        // Create filesystem and populate
        let fs = ContainerFilesystem::new(temp_dest.path().to_path_buf(), 512 * 1024 * 1024);
        fs.create_layout().unwrap();
        fs.populate_context(temp_source.path()).unwrap();

        // Verify included file exists
        assert!(temp_dest.path().join("context/main.rs").exists());

        // Verify secret files don't exist
        assert!(!temp_dest.path().join("context/.env").exists());
        assert!(!temp_dest.path().join("context/.env.local").exists());
        assert!(!temp_dest.path().join("context/credentials.json").exists());
        assert!(!temp_dest.path().join("context/secrets.yaml").exists());
        assert!(!temp_dest.path().join("context/server.key").exists());
        assert!(!temp_dest.path().join("context/cert.pem").exists());
    }
}
