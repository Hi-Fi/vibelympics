# Use Chainguard's minimal Python image (distroless, minimal attack surface)
FROM cgr.dev/chainguard/python:latest-dev AS builder

# Set working directory
WORKDIR /app

# Copy the auditor script and lib modules
COPY npm_auditor.py .
COPY lib/ ./lib/
COPY requirements.txt ./

# Install Python requirements into the builder image so they are available at runtime
RUN python3 -m pip install --no-cache-dir -r requirements.txt || true

# Use the runtime image (even more minimal, non-root by default)
FROM cgr.dev/chainguard/python:latest

# Set working directory
WORKDIR /app

# Copy the script and lib from builder
COPY --from=builder /app/npm_auditor.py .
COPY --from=builder /app/lib ./lib
COPY --from=builder /usr/local/lib/python3.*/site-packages /usr/local/lib/python3.*/site-packages

# Chainguard images run as non-root by default (uid 65532)
# No need to explicitly set USER

# Set the entrypoint to the auditor script
ENTRYPOINT ["python", "/app/npm_auditor.py"]

# Default to showing help if no arguments provided
CMD ["--help"]
