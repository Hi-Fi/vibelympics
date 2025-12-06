# Docker Usage

## Building the Image

```bash
docker build -t npm-auditor:latest .
```

## Usage Examples

### Audit a package-lock.json file
```bash
# From file
docker run -v $(pwd):/data npm-auditor /data/package-lock.json

# From stdin
cat package-lock.json | docker run -i npm-auditor - --format npm
```

### Audit yarn.lock
```bash
cat yarn.lock | docker run -i npm-auditor - --format yarn
```

### Audit pnpm-lock.yaml
```bash
cat pnpm-lock.yaml | docker run -i npm-auditor - --format pnpm
```

### With debug output
```bash
docker run -i npm-auditor - --format yarn --debug < yarn.lock
```

### Filter by severity
```bash
docker run -i npm-auditor - --format npm --severity HIGH,CRITICAL < package-lock.json
```

## Security Features

This Docker image uses **Chainguard images** for enhanced security:

- ✅ **Distroless**: Minimal attack surface with no shell, package managers, or unnecessary binaries
- ✅ **Non-root**: Runs as user `65532` (nonroot) by default
- ✅ **Multi-stage build**: Builder stage separated from runtime
- ✅ **Minimal layers**: Optimized for size and security
- ✅ **Regularly updated**: Chainguard images are automatically updated for CVEs

## Image Size

The final image is extremely small (~50-60MB) due to Chainguard's distroless approach.

```bash
docker images npm-auditor
```
