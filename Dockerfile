FROM python:3.11-slim

WORKDIR /shellbreaker

# System deps: javap (for bytecode inspection), curl (healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
        default-jdk-headless \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies — install torch CPU-only to keep image lean
COPY requirements.txt .
RUN pip install --no-cache-dir \
        torch==2.2.2+cpu torchvision==0.17.2+cpu \
        --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir \
        pillow tqdm fastapi uvicorn python-multipart scikit-learn

# Copy project files
COPY scripts/  scripts/
COPY output/   output/
COPY agent/    agent/
COPY libs/     libs/

# Mount point for files the user wants to scan
VOLUME ["/scan"]

# Results written here by default (also mountable)
VOLUME ["/results"]

ENV DOCKER_HOST=unix:///var/run/docker.sock

ENTRYPOINT ["python", "scripts/scan_bulk.py"]
CMD ["--help"]
