# 📦🔍 NPM Package Auditor

A secure, lightweight command-line tool to audit npm packages and lock files for vulnerabilities without installing them.

## ✨ Features

- **Multi-Format Support**: Audit `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`
- **Dependency-Free**: Built with standard Python 3 libraries only
- **Security Focused**: Checks the [OSV](https://osv.dev) database for known vulnerabilities
- **Performance Optimized**: Batch API queries for fast lock file auditing
- **Bundled Dependencies**: Tracks and reports transitive dependencies separately
- **Local Filtering**: Option to ignore network-based vulnerabilities for CLI/local apps
- **Containerized**: Secure Docker image using Chainguard distroless base
- **Stdin Support**: Pipe lock files directly for CI/CD integration
- **Safe**: Audits without `npm install` or executing package code

## 🚀 Usage

### Prerequisites
- Python 3.x installed (or use Docker)

### Command Line

**Audit a package:**
```bash
python3 npm_auditor.py <package-name> [--version VERSION]
````

**Audit lock files:**

```bash
# NPM (package-lock.json)
python3 npm_auditor.py package-lock.json

# Yarn
python3 npm_auditor.py yarn.lock --format yarn

# PNPM
python3 npm_auditor.py pnpm-lock.yaml --format pnpm
```

**From stdin (useful for CI/CD):**

```bash
cat package-lock.json | python3 npm_auditor.py - --format npm
cat yarn.lock | python3 npm_auditor.py - --format yarn
```

**Filter by severity:**

```bash
python3 npm_auditor.py express --severity HIGH,CRITICAL
python3 npm_auditor.py package-lock.json --severity MEDIUM,HIGH,CRITICAL
```

**Filter by attack vector (Local only):**
Useful for CLI apps where network-based server vulnerabilities are not relevant.

```bash
python3 npm_auditor.py my-cli-app --local
```

**Enable debug output:**

```bash
python3 npm_auditor.py express --debug
```

### Docker

**Build the image:**

```bash
docker build -t npm-auditor .
```

**Run with stdin:**

```bash
cat package-lock.json | docker run -i npm-auditor - --format npm
cat yarn.lock | docker run -i npm-auditor - --format yarn
```

**Run with volume mount:**

```bash
docker run -v $(pwd):/data npm-auditor /data/package-lock.json
```

See [DOCKER.md](DOCKER.md) for detailed Docker usage.

## 📊 Output

The tool provides detailed vulnerability reports with:

  - **CVE identifiers** and severity scores (CVSS v2/v3)
  - **Fixed versions** for each vulnerability
  - **Direct vs Bundled dependencies** separated into distinct tables
  - **Update instructions** for transitive dependencies
  - **Comprehensive summary** with issue counts

## 🛠️ How it Works

1.  Fetches package metadata from `registry.npmjs.org`
2.  Parses lock files (npm/yarn/pnpm formats)
3.  Batch queries OSV API for vulnerability data
4.  Traces dependency paths for bundled packages
5.  Calculates CVSS scores and severity ratings
6.  Outputs formatted tables with actionable insights

## 🔒 Security

  - **Docker**: Uses Chainguard distroless images (non-root, minimal attack surface)
  - **No execution**: Never executes package code
  - **Read-only**: Only reads metadata and lock files
  - **Trusted sources**: Queries official npm registry and OSV database

## 📝 Examples

**Audit a package with known vulnerabilities:**

```bash
python3 npm_auditor.py lodash --version 4.17.0
```

**Audit a CLI tool ignoring server-side issues:**

```bash
python3 npm_auditor.py my-cli-tool --local
```

**Audit a lock file with debug output:**

```bash
python3 npm_auditor.py package-lock.json --debug
```

**CI/CD pipeline example:**

```bash
# In GitHub Actions, GitLab CI, etc.
cat package-lock.json | docker run -i npm-auditor - --format npm --severity HIGH,CRITICAL
```

## 🧪 Development

### Project Structure

```
round_2/
├── npm_auditor.py      # Main entry point (511 lines)
├── lib/                # Modular libraries
│   ├── api_client.py   # NPM Registry & OSV API clients
│   ├── cvss.py         # CVSS score calculation
│   ├── formatters.py   # Output formatting & colors
│   └── parsers.py      # Lock file parsers (npm/yarn/pnpm)
├── tests/              # Unit tests
│   └── test_cvss.py    # CVSS module tests
├── Dockerfile          # Chainguard-based container
└── .dockerignore       # Build exclusions
```

### Running Tests

**Unit tests (requires Python 3):**

```bash
cd round_2
python3 tests/test_cvss.py
```

**Integration tests with sample files:**

```bash
python3 npm_auditor.py test_yarn.lock --format yarn
python3 npm_auditor.py test_pnpm.lock.yaml --format pnpm
python3 npm_auditor.py package-lock.json
```

**Docker integration test:**

```bash
cat test_pnpm.lock.yaml | docker run -i npm-auditor - --format pnpm
```

### Module Overview

| Module | Purpose |
|--------|---------|
| `api_client.py` | HTTP calls to npm registry and OSV vulnerability API |
| `cvss.py` | Calculate CVSS v2/v3 scores, severity ratings |
| `formatters.py` | ANSI colors, table formatting, summary output |
| `parsers.py` | Parse yarn.lock, pnpm-lock.yaml, npm dependency graphs |

## 📄 License

This tool is provided as-is for security auditing purposes.
