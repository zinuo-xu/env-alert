use crate::rules::DetectionRule;

/// Returns detection rules for API keys and secrets
pub fn get_secrets_patterns() -> Vec<DetectionRule> {
    let rules = crate::rules::get_rules();
    rules.into_iter().filter(|r| r.category == "secrets").collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_patterns_exist() {
        let patterns = get_secrets_patterns();
        assert!(!patterns.is_empty(), "Should have secrets patterns");
        let names: Vec<&str> = patterns.iter().map(|p| p.name).collect();
        assert!(names.contains(&"aws_access_key_id"));
        assert!(names.contains(&"github_token"));
        assert!(names.contains(&"openai_api_key"));
        assert!(names.contains(&"stripe_live"));
    }
}
