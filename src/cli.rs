//! CLI argument parsing using clap 4.x derive feature

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Nucleus - Extremely lightweight Docker alternative for agents
#[derive(Parser, Debug)]
#[command(name = "nucleus")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a command in an isolated container
    Run(RunArgs),
}

/// Arguments for the `nucleus run` command
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Path to the context directory (pre-populated into container)
    #[arg(short = 'C', long, value_name = "DIR")]
    pub context: PathBuf,

    /// Memory limit for the container (e.g., 512M, 1G)
    #[arg(short, long, value_name = "BYTES", default_value = "512M")]
    pub memory: String,

    /// CPU limit for the container (number of cores, e.g., 2, 0.5)
    #[arg(short = 'p', long, value_name = "CORES", default_value = "1")]
    pub cpus: f64,

    /// Runtime to use for container execution
    #[arg(short, long, value_name = "RUNTIME", default_value = "native")]
    pub runtime: String,

    /// Hostname for the container (optional)
    #[arg(short = 'H', long, value_name = "NAME")]
    pub hostname: Option<String>,

    /// Command to execute in the container
    #[arg(required = true, trailing_var_arg = true)]
    pub command: Vec<String>,
}

impl RunArgs {
    /// Parse memory string into bytes
    /// Supports formats: 512M, 1G, 2GB, 512 (assumes bytes)
    pub fn memory_bytes(&self) -> Result<u64, String> {
        parse_size(&self.memory)
    }

    /// Get the executable and arguments from the command
    pub fn command_parts(&self) -> (&str, &[String]) {
        match self.command.as_slice() {
            [exe, args @ ..] => (exe, args),
            [] => ("", &[]),
        }
    }
}

/// Parse a size string (e.g., "512M", "1G") into bytes
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim().to_uppercase();

    // Handle the suffix
    let (num_str, multiplier) = if s.ends_with("GB") {
        (&s[..s.len() - 2], 1024u64 * 1024 * 1024)
    } else if s.ends_with("G") {
        (&s[..s.len() - 1], 1024u64 * 1024 * 1024)
    } else if s.ends_with("MB") {
        (&s[..s.len() - 2], 1024u64 * 1024)
    } else if s.ends_with("M") {
        (&s[..s.len() - 1], 1024u64 * 1024)
    } else if s.ends_with("KB") {
        (&s[..s.len() - 2], 1024u64)
    } else if s.ends_with("K") {
        (&s[..s.len() - 1], 1024u64)
    } else if s.ends_with("B") {
        (&s[..s.len() - 1], 1u64)
    } else {
        (s.as_str(), 1u64)
    };

    let num: u64 = num_str.parse().map_err(|_| format!("Invalid size: {}", s))?;
    Ok(num * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("1024").unwrap(), 1024);
    }

    #[test]
    fn test_parse_size_kilobytes() {
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("2KB").unwrap(), 2048);
        assert_eq!(parse_size("512k").unwrap(), 512 * 1024);
    }

    #[test]
    fn test_parse_size_megabytes() {
        assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
    }

    #[test]
    fn test_parse_size_gigabytes() {
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("2GB").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_with_spaces() {
        assert_eq!(parse_size(" 512M ").unwrap(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_invalid() {
        assert!(parse_size("abc").is_err());
        assert!(parse_size("").is_err());
    }
}
