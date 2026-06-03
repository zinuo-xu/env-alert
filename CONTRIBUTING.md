# Contributing to env-alert

First off, thank you for considering contributing to env-alert! We welcome contributions from everyone.

## Code of Conduct

We are committed to providing a welcoming and inclusive experience for everyone. Be respectful, constructive, and professional.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/zinuo-xu/env-alert/issues)
2. If not, create a new issue with:
   - A clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Rust version)
   - Example code (if applicable)

### Suggesting Features

1. Open an issue describing the feature
2. Explain why it would be useful
3. Include examples of how it would work

### Adding Detection Patterns

1. Add the regex pattern to `src/rules.rs`
2. Add corresponding tests in the `tests` module
3. Run `cargo test` to verify
4. Update the README pattern list if applicable

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests: `cargo test`
5. Run clippy: `cargo clippy -- -D warnings`
6. Commit with clear messages
7. Push to your fork
8. Open a Pull Request

## Development Setup

```bash
git clone https://github.com/zinuo-xu/env-alert.git
cd env-alert
cargo build
cargo test
```

## Project Structure

```
env-alert/
├── src/
│   ├── main.rs          # CLI entry point with clap
│   ├── scanner.rs       # File scanner & git integration
│   ├── rules.rs         # Detection rule engine
│   ├── patterns/        # Pattern categories
│   ├── reporter.rs      # Colored terminal output
│   └── config.rs        # TOML configuration
├── tests/               # Integration tests
└── .pre-commit-hook.sh  # Git hook script
```

## Coding Standards

- Run `cargo fmt` before committing
- Ensure `cargo clippy -- -D warnings` passes
- Write tests for new functionality
- Keep functions focused and small
- Document public API items

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_aws_key_detection

# Run integration tests
cargo test --test integration_test
```

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create a tag: `git tag v0.1.0`
4. Push tag: `git push origin v0.1.0`
5. CI will build and publish to GitHub Releases

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
