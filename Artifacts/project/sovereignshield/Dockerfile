# SovereignShield — Shiny for Python on HuggingFace Spaces
# Port 7860 required by Spaces
FROM python:3.11-slim

# Install curl (for OPA download) and OPA binary (static, no glibc dependency)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -L -o /usr/local/bin/opa \
        https://github.com/open-policy-agent/opa/releases/download/v0.70.0/opa_linux_amd64_static \
    && chmod +x /usr/local/bin/opa

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# HF Spaces inject secrets as env vars; load_dotenv finds .env if present
EXPOSE 7860
CMD ["shiny", "run", "app.py", "--host", "0.0.0.0", "--port", "7860"]
