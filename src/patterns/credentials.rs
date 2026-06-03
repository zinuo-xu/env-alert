use crate::rules::DetectionRule;

/// Returns detection rules for passwords and credentials
pub fn get_credential_patterns() -> Vec<DetectionRule> {
    let rules = crate::rules::get_rules();
    rules.into_iter().filter(|r| r.category == "credentials").collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_patterns_exist() {
        let patterns = get_credential_patterns();
        assert!(!patterns.is_empty(), "Should have credential patterns");
        let names: Vec<&str> = patterns.iter().map(|p| p.name).collect();
        assert!(names.contains(&"password_assignment"));
        assert!(names.contains(&"private_key"));
        assert!(names.contains(&"db_connection_url"));
    }
}
