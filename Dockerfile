# ==============================================================================
# LIA Sovereign Formal Verification & Adversarial Challenge Arena Container
# ==============================================================================
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x run_challenge.sh

ENTRYPOINT ["python3", "challenge_runner.py"]
CMD ["--all"]
