use crate::rules::DetectionRule;

/// Returns detection rules for .env file references
pub fn get_env_file_patterns() -> Vec<DetectionRule> {
    let rules = crate::rules::get_rules();
    rules.into_iter().filter(|r| r.category == "env_files").collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_file_patterns() {
        let patterns = get_env_file_patterns();
        assert!(!patterns.is_empty(), "Should have env_file patterns");
        let names: Vec<&str> = patterns.iter().map(|p| p.name).collect();
        assert!(names.contains(&"env_file_reference"));
    }
}
