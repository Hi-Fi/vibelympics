# --- Stage 1: Builder (Generate Certs & Build) ---
FROM cgr.dev/chainguard/python:latest-dev as builder

USER root

# Install build tools and OpenSSL
RUN apk update && apk add build-base libjpeg-turbo-dev zlib-dev openssl

WORKDIR /app

# Generate Self-Signed SSL Certificate (Owned by Root here)
RUN openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost"

# Create Virtual Environment & Install
RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 2: Runtime (Secure & Hardened) ---
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

# 1. Copy the environment
COPY --from=builder /app/venv /app/venv

# 2. THE FIX: Copy keys and change owner to 'nonroot'
# Chainguard runs as user 'nonroot' (UID 65532) by default.
# We must ensure this user owns the keys so it can read them.
COPY --from=builder --chown=nonroot:nonroot /app/cert.pem /app/cert.pem
COPY --from=builder --chown=nonroot:nonroot /app/key.pem /app/key.pem

# Copy compiled library dependencies (standard copy is fine for libs)
COPY --from=builder /usr/lib/libjpeg.so* /usr/lib/
COPY --from=builder /usr/lib/libz.so* /usr/lib/

COPY app.py .

ENV PATH="/app/venv/bin:$PATH"
ENV PORT=8080

EXPOSE 8080

# Run Gunicorn
ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--certfile", "cert.pem", "--keyfile", "key.pem", "--workers", "2", "app:app"]