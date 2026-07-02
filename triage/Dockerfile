# SOC Dashboard - Python Triage Layer
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fetch_alerts.py enrich.py summarize.py main.py ./

# Credentials are injected at runtime via environment variables / --env-file,
# never baked into the image. See .env.example for required variables.
ENTRYPOINT ["python", "main.py"]
