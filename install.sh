#!/bin/bash
set -e

echo "============================================"
echo " Uplinx Meta Manager - Installer"
echo "============================================"

# Check Python 3.10+
if ! python3 -c "import sys; assert sys.version_info >= (3, 10)" 2>/dev/null; then
    echo "ERROR: Python 3.10+ is required."
    echo "Install from https://www.python.org/downloads/"
    exit 1
fi

echo "[1/8] Creating virtual environment..."
python3 -m venv venv

echo "[2/8] Activating virtual environment..."
source venv/bin/activate

echo "[3/8] Upgrading pip..."
pip install --upgrade pip --quiet

echo "[4/8] Installing dependencies..."
pip install -r requirements.txt --quiet

echo "[5/8] Setting up configuration..."
if [ ! -f .env ]; then
    cp .env.example .env
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    # Use Python to replace values (handles special chars safely)
    python3 -c "
import re
with open('.env', 'r') as f:
    content = f.read()
content = content.replace('generate_64_char_random_string_here', '$SECRET_KEY')
content = content.replace('generate_fernet_key_here', '$ENCRYPTION_KEY')
with open('.env', 'w') as f:
    f.write(content)
"
    echo "Generated security keys in .env"
fi

echo "[6/8] Creating directories..."
mkdir -p uploads skills/global skills/clients

echo "[7/8] Initializing database..."
python3 -c "import asyncio; from database import init_db; asyncio.run(init_db())"

echo "[8/8] Done!"
echo ""
echo "============================================"
echo " NEXT STEPS:"
echo " 1. Edit .env with your API credentials"
echo " 2. Run ./start.sh to launch the app"
echo "============================================"
