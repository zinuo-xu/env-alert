use crate::rules::DetectionRule;

/// Returns detection rules for JWT, OAuth, and other tokens
pub fn get_token_patterns() -> Vec<DetectionRule> {
    let rules = crate::rules::get_rules();
    rules.into_iter().filter(|r| r.category == "tokens").collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_patterns_exist() {
        let patterns = get_token_patterns();
        assert!(!patterns.is_empty(), "Should have token patterns");
        let names: Vec<&str> = patterns.iter().map(|p| p.name).collect();
        assert!(names.contains(&"jwt_token"));
        assert!(names.contains(&"slack_token"));
        assert!(names.contains(&"webhook_url"));
    }
}
