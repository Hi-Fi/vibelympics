# Use Chainguard's minimal Python image (distroless, minimal attack surface)
FROM cgr.dev/chainguard/python:latest-dev AS builder

# Set working directory
WORKDIR /app

# Copy the auditor script
COPY npm_auditor.py .

# Use the runtime image (even more minimal, non-root by default)
FROM cgr.dev/chainguard/python:latest

# Set working directory
WORKDIR /app

# Copy the script from builder
COPY --from=builder /app/npm_auditor.py .

# Chainguard images run as non-root by default (uid 65532)
# No need to explicitly set USER

# Set the entrypoint to the auditor script
ENTRYPOINT ["python", "/app/npm_auditor.py"]

# Default to showing help if no arguments provided
CMD ["--help"]
