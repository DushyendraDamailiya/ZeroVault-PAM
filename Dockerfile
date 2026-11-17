# ZeroVault PAM - Enterprise Production Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system utilities (SSH client, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY pam_backend/ ./pam_backend/
COPY frontend/ ./frontend/
COPY README.md .

# Expose Web Dashboard (5005) and Live SSH Protocol Proxy (2222)
EXPOSE 5005 2222

# Start ZeroVault PAM
CMD ["python", "-m", "pam_backend.app"]
