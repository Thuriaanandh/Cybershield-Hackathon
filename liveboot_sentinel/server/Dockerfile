# LiveBoot Sentinel - Server Dockerfile
# Multi-stage build for minimal production image

FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt --target /build/deps

# ─── Production Stage ─────────────────────────────────────────────────────────
FROM python:3.11-slim

# Security: run as non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -s /bin/false sentinel

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /build/deps /usr/local/lib/python3.11/site-packages

# Copy server source
COPY api.py database.py models.py alert_handler.py websocket.py ./

# Create data directory with correct ownership
RUN mkdir -p /var/lib/liveboot_sentinel && \
    chown -R sentinel:sentinel /var/lib/liveboot_sentinel /app

# Drop to non-root
USER sentinel

# Expose HTTPS port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request, ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; urllib.request.urlopen('https://localhost:8443/health', context=ctx)"

# Start server with TLS
CMD ["uvicorn", "api:app", \
     "--host", "0.0.0.0", \
     "--port", "8443", \
     "--ssl-keyfile", "/certs/server.key", \
     "--ssl-certfile", "/certs/server.crt", \
     "--workers", "2", \
     "--access-log", \
     "--log-level", "info"]
