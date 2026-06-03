# env-alert

[![CI](https://github.com/zinuo-xu/env-alert/actions/workflows/ci.yml/badge.svg)](https://github.com/zinuo-xu/env-alert/actions/workflows/ci.yml)
[![Release](https://github.com/zinuo-xu/env-alert/actions/workflows/release.yml/badge.svg)](https://github.com/zinuo-xu/env-alert/actions/workflows/release.yml)
[![Crates.io](https://img.shields.io/badge/crates.io-0.1.0-orange)](https://crates.io/crates/env-alert)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-blue)](https://www.rust-lang.org)

**env-alert** is a blazingly fast Rust CLI tool that scans your codebase for exposed secrets, API keys, credentials, and sensitive tokens before they make it into your repository.

## Features

- 🚀 **Blazing Fast** — Parallel file scanning with rayon
- 🔍 **30+ Detection Patterns** — AWS, GitHub, Stripe, OpenAI, Google, Slack, JWT, OAuth, and more
- 🎨 **Colored Output** — Beautiful terminal output with severity highlighting
- 📊 **Entropy Analysis** — Reduces false positives by analyzing Shannon entropy
- ⚙️ **Configurable** — TOML-based configuration with allowlist support
- 🔗 **Pre-commit Hook** — Automatic git pre-commit hook installation
- 📄 **JSON Output** — Machine-readable output for CI/CD integration
- 🧹 **.gitignore Aware** — Respects your existing .gitignore rules

## Installation

### Using Cargo

```bash
cargo install env-alert
```

### Using the Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/zinuo-xu/env-alert/main/install.sh | bash
```

### From Source

```bash
git clone https://github.com/zinuo-xu/env-alert.git
cd env-alert
cargo build --release
./target/release/env-alert --help
```

## Usage

### Scan a directory

```bash
# Scan current directory
env-alert scan

# Scan specific directory
env-alert scan /path/to/project

# JSON output
env-alert scan --format json

# Use custom config
env-alert scan --config .env-alert.toml
```

### Install pre-commit hook

```bash
env-alert install-hook
```

### Initialize configuration

```bash
env-alert init
```

## Configuration

Create a `.env-alert.toml` file:

```toml
max_depth = 50
max_file_size_bytes = 1048576
max_line_length = 10000
min_entropy = 3.5
extensions = ["rs", "py", "js", "ts", "go", "rb", "env"]
severity_levels = ["high", "medium", "low"]

[allowlist]
items = ["example", "placeholder", "test"]

[ignore_patterns]
items = ["node_modules", "vendor", ".git"]
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No secrets found |
| 1 | Low/medium severity findings |
| 2 | High severity findings |

## Supported Patterns

### API Keys
- AWS Access Key ID & Secret Access Key
- GitHub Personal Access Tokens
- Stripe Live/Test API Keys
- OpenAI API & Organization Keys
- Google API Keys & OAuth Secrets
- Heroku API Keys
- Generic API Keys

### Credentials
- Password assignments
- Secret key assignments
- Database connection URLs
- Private SSH/RSA/DSA keys

### Tokens
- JWT (JSON Web Tokens)
- OAuth tokens & client IDs
- Slack tokens & webhooks
- Webhook URLs
- Bearer tokens

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
