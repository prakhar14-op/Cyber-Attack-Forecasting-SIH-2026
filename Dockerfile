FROM python:3.12-slim

# Install system dependencies required for packet inspection, PCAP reading, and C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Non-root user with UID 1000 for Hugging Face Spaces compatibility
RUN useradd -m -u 1000 user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    PORT=7860 \
    HOST=0.0.0.0 \
    SIH26_HMAC_KEY=dev-frontend-key \
    SIH26_LEDGER_KEY=dev-frontend-key

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code, models, configs, and assets (ignoring frontend via .dockerignore)
COPY . .

# Ensure demo artifacts are prepared if needed
RUN python scripts/bootstrap_demo_artifacts.py || true

# Set permissions for non-root user
RUN chown -R user:user /app
USER user

# Hugging Face Spaces standard port
EXPOSE 7860

# Run the aiohttp engine server
CMD ["python", "-m", "engine.server"]
