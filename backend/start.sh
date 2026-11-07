#!/bin/bash
# =============================================================================
# AI Web Auditor — Startup Script for Render.com
# Starts the background worker FIRST, then the FastAPI server (foreground).
# =============================================================================

echo "🔧 Starting AI Web Auditor Backend..."

# Start the background worker (consumes jobs from Redis queue)
echo "🏭 Launching worker.py in background..."
python worker.py &
WORKER_PID=$!

# Start the FastAPI API server (must stay in foreground for Render health checks)
echo "🚀 Launching FastAPI server on port $PORT..."
uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
