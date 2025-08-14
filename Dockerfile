# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps (curl for debugging; tzdata for logs)
RUN apt-get update && apt-get install -y --no-install-recommends     ca-certificates tzdata curl &&     rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY pyproject.toml ./
COPY sample_config.yaml ./config.yaml

# Default command runs help
CMD ["python", "-m", "auditor", "--config", "config.yaml"]
