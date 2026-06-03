pub mod secrets;
pub mod env_files;
pub mod credentials;
pub mod tokens;

use crate::rules::DetectionRule;

/// Get all detection patterns from all categories
pub fn get_all_patterns() -> Vec<DetectionRule> {
    let mut all = Vec::new();
    all.extend(secrets::get_secrets_patterns());
    all.extend(env_files::get_env_file_patterns());
    all.extend(credentials::get_credential_patterns());
    all.extend(tokens::get_token_patterns());
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_patterns_have_names() {
        let patterns = get_all_patterns();
        assert!(!patterns.is_empty(), "Should have at least one pattern");
        for p in &patterns {
            assert!(!p.name.is_empty(), "Pattern should have a name");
            assert!(!p.severity.is_empty(), "Pattern should have a severity");
            assert!(["high", "medium", "low"].contains(&p.severity), "Invalid severity: {}", p.severity);
        }
    }

    #[test]
    fn test_all_categories_present() {
        let patterns = get_all_patterns();
        let categories: std::collections::HashSet<&str> =
            patterns.iter().map(|p| p.category).collect();
        assert!(categories.contains("secrets"), "Missing secrets category");
        assert!(categories.contains("env_files"), "Missing env_files category");
        assert!(categories.contains("credentials"), "Missing credentials category");
        assert!(categories.contains("tokens"), "Missing tokens category");
    }
}
