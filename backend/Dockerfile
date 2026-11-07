# =============================================================================
# AI Web Auditor — Backend Dockerfile
# Optimized for Render.com Free Tier (512 MB RAM)
# Runs FastAPI API + Background Worker + Playwright Chromium
# =============================================================================

FROM python:3.11-slim

# --- System dependencies for Playwright Chromium ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libxshmfence1 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# --- Working directory ---
WORKDIR /app

# --- Install Python dependencies ---
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Install ONLY Chromium (skip Firefox/WebKit to save ~400 MB) ---
RUN playwright install --with-deps chromium

# --- Copy application code ---
COPY main.py .
COPY worker.py .
COPY start.sh .
RUN chmod +x start.sh

# --- Expose API port ---
EXPOSE 8000

# --- Start both API + Worker ---
CMD ["bash", "start.sh"]
