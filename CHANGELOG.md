# Changelog

## [0.1.0] - 2026-06-03

### Added
- Initial release of env-alert
- Parallel file scanning with `.gitignore` awareness
- 30+ detection patterns for common secrets and credentials:
  - AWS keys (Access Key ID, Secret Access Key)
  - GitHub tokens (personal access, legacy)
  - Stripe API keys (live, test, publishable)
  - OpenAI API and organization keys
  - Google API keys and OAuth secrets
  - Slack tokens and webhooks
  - JWT, OAuth, and bearer tokens
  - Database connection URLs (PostgreSQL, MySQL, MongoDB, Redis)
  - Private SSH/RSA/DSA keys
  - Password and secret assignments
  - .env file references
- Shannon entropy analysis for false positive reduction
- Colored terminal output with severity-based highlighting
- JSON output format for CI/CD integration
- TOML-based configuration with allowlist support
- Git pre-commit hook installer
- `env-alert init` for quick configuration setup
- GitHub Actions CI pipeline (test, lint, build)
- GitHub Actions release pipeline (cross-platform binaries)
- Pre-built binaries for Linux, macOS, and Windows via GitHub Releases
- Comprehensive test suite covering all detection patterns
