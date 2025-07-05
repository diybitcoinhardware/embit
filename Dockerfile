FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    ca-certificates \
    autoconf \
    automake \
    libtool \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy project files
COPY . /app

# Install Python dependencies (including dev)
RUN pip install --upgrade pip && pip install .[dev]

# Make run_tests.sh executable
RUN chmod +x /app/run_tests.sh

# Entrypoint
ENTRYPOINT ["/app/run_tests.sh"] 