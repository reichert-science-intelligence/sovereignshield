FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L -o /usr/local/bin/opa \
    https://github.com/open-policy-agent/opa/releases/download/v0.70.0/opa_linux_amd64_static \
    && chmod +x /usr/local/bin/opa \
    && opa version

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
       shiny shinyswatch \
       anthropic \
       supabase \
       smolagents \
       chromadb==0.5.23 \
       sentence-transformers==3.0.0 \
       pandas numpy plotnine \
       python-hcl2 pyyaml jsonschema \
       sqlalchemy aiosqlite \
       python-dotenv httpx structlog tenacity

COPY Artifacts/ ./Artifacts/

RUN mkdir -p /tmp/chroma_db /tmp/sovereignshield_data

EXPOSE 7860

WORKDIR /app/Artifacts
CMD ["shiny", "run", "project/sovereignshield/app.py", \
     "--host", "0.0.0.0", "--port", "7860"]
