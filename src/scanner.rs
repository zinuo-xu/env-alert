use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::config::Config;
use crate::rules;
use crate::patterns;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub file_path: PathBuf,
    pub line_number: usize,
    pub column: usize,
    pub line_content: String,
    pub pattern_name: String,
    pub severity: String,
    pub matched_text: String,
    pub entropy: f64,
}

/// Scan a directory for exposed secrets and credentials
pub fn scan_directory(path: &Path, config: &Config, use_gitignore: bool) -> Vec<ScanResult> {
    let mut results: Vec<ScanResult> = Vec::new();
    let max_file_size = config.max_file_size_bytes;
    let extension_whitelist: Option<Vec<String>> = if config.extensions.is_empty() {
        None
    } else {
        Some(config.extensions.clone())
    };

    let files: Vec<PathBuf> = if use_gitignore {
        WalkBuilder::new(path)
            .hidden(false)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .max_depth(Some(config.max_depth))
            .build()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|f| f.is_file()).unwrap_or(false))
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        WalkDir::new(path)
            .max_depth(config.max_depth)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect()
    };

    // Filter by extension if specified
    let files: Vec<PathBuf> = if let Some(ref whitelist) = extension_whitelist {
        files
            .into_iter()
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| whitelist.contains(&e.to_lowercase()))
                    .unwrap_or(true)
            })
            .collect()
    } else {
        files
    };

    // Ignore patterns from config
    let ignore_patterns = &config.ignore_patterns;

    let filtered: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| {
            !ignore_patterns.iter().any(|pat| {
                p.to_string_lossy().to_lowercase().contains(&pat.to_lowercase())
            })
        })
        .collect();

    // Scan files in parallel using rayon
    let file_results: Vec<Vec<ScanResult>> = filtered
        .par_iter()
        .filter_map(|file_path| {
            let meta = std::fs::metadata(file_path).ok()?;
            if meta.len() > max_file_size as u64 {
                return None;
            }
            let content = std::fs::read_to_string(file_path).ok()?;
            let file_results = scan_content(file_path, &content, config);
            Some(file_results)
        })
        .collect();

    for mut fr in file_results {
        results.append(&mut fr);
    }

    results
}

/// Scan file content for secret patterns
pub fn scan_content(file_path: &Path, content: &str, config: &Config) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let patterns = patterns::get_all_patterns();
    let max_line_length = config.max_line_length;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim_end();
        if line.len() > max_line_length as usize {
            continue;
        }

        // Check config allowlist
        if config.allowlist.iter().any(|w| line.contains(w)) {
            continue;
        }

        for pattern in &patterns {
            // Skip if pattern severity is below config threshold
            if !config.is_severity_enabled(&pattern.severity) {
                continue;
            }

            for mat in pattern.regex.find_iter(line) {
                let matched = mat.as_str();
                let entropy = calculate_entropy(matched);

                // Apply entropy threshold filtering
                if entropy < config.min_entropy {
                    continue;
                }

                results.push(ScanResult {
                    file_path: file_path.to_path_buf(),
                    line_number: line_num + 1,
                    column: mat.start() + 1,
                    line_content: line.to_string(),
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    matched_text: matched.to_string(),
                    entropy,
                });
            }
        }
    }

    results
}

/// Calculate Shannon entropy of a string to distinguish random secrets from hardcoded values
pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = std::collections::HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let entropy: f64 = freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        if p > 0.0 {
            acc - p * p.log2()
        } else {
            acc
        }
    });

    entropy
}

/// Install pre-commit hook into a git repository
pub fn install_pre_commit_hook(hook_dir: &Path) -> std::io::Result<PathBuf> {
    let hook_path = hook_dir.join("pre-commit");
    let hook_script = include_str!("../.pre-commit-hook.sh");

    if !hook_dir.exists() {
        std::fs::create_dir_all(hook_dir)?;
    }

    std::fs::write(&hook_path, hook_script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(hook_path)
}

# docs: add FAQ section to documentation (incremental change 1)

# chore: update dependencies to latest versions (incremental change 2)

# refactor: improve type hints and add mypy compliance (incremental change 3)

# fix: handle empty input gracefully in edge cases (incremental change 4)

# refactor: extract common logic into shared utility module (incremental change 5)

# feat: add progress bar for long-running operations (incremental change 6)

# docs: improve installation instructions (incremental change 7)

# perf: implement lazy loading for large datasets (incremental change 8)

# feat: export results to multiple formats (incremental change 9)

# fix: validate input before processing to prevent crash (incremental change 10)
