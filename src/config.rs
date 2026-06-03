use std::path::Path;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Configuration for env-alert scans
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Maximum depth to scan directories
    pub max_depth: usize,
    /// Maximum file size in bytes to scan (default: 1MB)
    pub max_file_size_bytes: usize,
    /// Maximum line length to consider (skips minified files)
    pub max_line_length: usize,
    /// Minimum entropy threshold for flagging secrets (3.5 default)
    pub min_entropy: f64,
    /// File extensions to scan (empty means all)
    pub extensions: Vec<String>,
    /// Glob patterns to ignore
    pub ignore_patterns: Vec<String>,
    /// Severity levels to report (high, medium, low)
    pub severity_levels: Vec<String>,
    /// Lines containing these strings will be ignored
    pub allowlist: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_depth: 50,
            max_file_size_bytes: 1_048_576, // 1MB
            max_line_length: 10_000,
            min_entropy: 3.5,
            extensions: Vec::new(),
            ignore_patterns: vec![
                "node_modules".to_string(),
                "vendor".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "__pycache__".to_string(),
                ".venv".to_string(),
                "venv".to_string(),
                "dist".to_string(),
                "build".to_string(),
                ".next".to_string(),
                "yarn.lock".to_string(),
                "package-lock.json".to_string(),
                "Cargo.lock".to_string(),
                "*.exe".to_string(),
                "*.dll".to_string(),
                "*.so".to_string(),
                "*.dylib".to_string(),
                "*.bin".to_string(),
                "*.png".to_string(),
                "*.jpg".to_string(),
                "*.jpeg".to_string(),
                "*.gif".to_string(),
                "*.ico".to_string(),
                "*.svg".to_string(),
                "*.woff".to_string(),
                "*.woff2".to_string(),
                "*.eot".to_string(),
                "*.ttf".to_string(),
                "*.pdf".to_string(),
                "*.zip".to_string(),
                "*.tar".to_string(),
                "*.gz".to_string(),
                "*.mp4".to_string(),
                "*.mp3".to_string(),
            ],
            severity_levels: vec![
                "high".to_string(),
                "medium".to_string(),
                "low".to_string(),
            ],
            allowlist: vec![
                "example".to_string(),
                "EXAMPLE".to_string(),
                "placeholder".to_string(),
                "test".to_string(),
                "dummy".to_string(),
                "fake".to_string(),
                "changeme".to_string(),
                "CHANGEME".to_string(),
            ],
        }
    }
}

impl Config {
    /// Check if a severity level should be reported
    pub fn is_severity_enabled(&self, severity: &str) -> bool {
        self.severity_levels.contains(&severity.to_string())
    }

    /// Get the set of enabled severity levels
    pub fn enabled_severities(&self) -> HashSet<&str> {
        self.severity_levels.iter().map(|s| s.as_str()).collect()
    }
}

/// Load configuration from a TOML file
pub fn load_config(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

/// Try to load default config from .env-alert.toml in the current directory
pub fn try_load_default() -> Option<Config> {
    let path = Path::new(".env-alert.toml");
    if path.exists() {
        load_config(path).ok()
    } else {
        None
    }
}

/// Write a default configuration file
pub fn write_default_config(path: &Path) -> Result<(), std::io::Error> {
    let config = Config::default();
    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, toml_str)
}
