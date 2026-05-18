#!/bin/bash
set -e

echo "Starting Uplinx Meta Manager..."

if [ ! -f .env ]; then
    echo "ERROR: .env file not found. Run ./install.sh first."
    exit 1
fi

if grep -q "META_APP_ID=your_meta_app_id" .env; then
    echo "WARNING: META_APP_ID not configured. Please edit .env"
    exit 1
fi

source venv/bin/activate

echo "Launching server at http://localhost:8000"

# Open browser in background
(sleep 2 && (open http://localhost:8000 2>/dev/null || xdg-open http://localhost:8000 2>/dev/null || true)) &

uvicorn main:app --host 127.0.0.1 --port 8000 --reload
