FROM python:3.12-slim

# System dependencies required by the analysis engine:
#   libmagic1     -> python-magic (file type identification)
#   libfuzzy-dev  -> ssdeep (fuzzy hashing)
#   build-essential, python3-dev -> compiling yara-python / ssdeep wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    libfuzzy-dev \
    build-essential \
    python3-dev \
    libyara-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p storage/uploads storage/reports storage/pcaps

EXPOSE 8000

# NOTE for production (government deployment):
#   - Run as a non-root user
#   - Put a real ASGI process manager in front (this CMD is fine for a
#     single-node pilot; for HA use multiple uvicorn workers behind nginx,
#     or gunicorn -k uvicorn.workers.UvicornWorker)
#   - Terminate TLS at nginx (see deploy/nginx.conf), never expose 8000 directly
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
