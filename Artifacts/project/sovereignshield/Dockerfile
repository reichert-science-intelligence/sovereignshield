# SovereignShield — Shiny for Python on HuggingFace Spaces
# Port 7860 required by Spaces
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# HF Spaces inject secrets as env vars; load_dotenv finds .env if present
EXPOSE 7860
CMD ["shiny", "run", "app.py", "--host", "0.0.0.0", "--port", "7860"]
