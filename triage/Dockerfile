# SOC Dashboard - Python Triage Layer
# Multi-stage Docker build with non-root security isolation

# --- Stage 1: Build & Dependencies ---
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# --- Stage 2: Minimal Runtime ---
FROM python:3.12-slim AS runner

# Create unprivileged security user
RUN useradd -m -u 10001 -s /bin/bash appuser

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH

# Copy application source files
COPY config.py state.py fetch_alerts.py enrich.py summarize.py main.py ./

# Switch to non-root user
USER appuser

# Credentials are injected at runtime via environment variables / --env-file
ENTRYPOINT ["python", "main.py"]
