# --- Stage 1: Builder (Generate Certs, Build & TEST) ---
FROM cgr.dev/chainguard/python:latest-dev as builder

USER root

# Install build tools and OpenSSL
RUN apk update && apk add build-base libjpeg-turbo-dev zlib-dev openssl

WORKDIR /app

# Generate Self-Signed SSL Certificate
RUN openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost"

# Create Virtual Environment & Install
RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- NEW: Copy Source & Run Tests ---
# We copy the app code into the builder stage specifically to run tests.
COPY . .

# Run the unit tests. 
# If this command returns a non-zero exit code (failure), the build STOPS here.
RUN python tests.py

# --- Stage 2: Runtime (Secure & Hardened) ---
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

# 1. Copy the environment
COPY --from=builder /app/venv /app/venv

# 2. Copy keys and change owner to 'nonroot'
COPY --from=builder --chown=nonroot:nonroot /app/cert.pem /app/cert.pem
COPY --from=builder --chown=nonroot:nonroot /app/key.pem /app/key.pem

# Copy compiled library dependencies
COPY --from=builder /usr/lib/libjpeg.so* /usr/lib/
COPY --from=builder /usr/lib/libz.so* /usr/lib/

# Copy all application files
COPY . .

ENV PATH="/app/venv/bin:$PATH"
ENV PORT=8080

EXPOSE 8080

# Run Gunicorn
ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--certfile", "cert.pem", "--keyfile", "key.pem", "--workers", "2", "app:app"]