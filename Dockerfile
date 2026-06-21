FROM python:3.11-slim

WORKDIR /app

# pymupdf>=1.24 ships a self-contained wheel (libmupdf bundled); no system dep needed.
# Install Python dependencies first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create directories that the app writes to at runtime
RUN mkdir -p uploads data logs

# Non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Default port (Render / Railway inject $PORT at runtime)
EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
