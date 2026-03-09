FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY . .
EXPOSE 7860
ENV PYTHONUNBUFFERED=1

CMD ["shiny", "run", "app.py", "--host", "0.0.0.0", "--port", "7860"]
