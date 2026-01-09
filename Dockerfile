## -*- docker-image-name: "libmatch" -*-
FROM python:3.11-slim

LABEL maintainer="edg@cs.ucsb.edu"
LABEL description="LibMatch - Binary library function matcher using angr"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    binutils-multiarch \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Install autoblob (custom CLE loader)
RUN git clone https://github.com/subwire/autoblob /tmp/autoblob && \
    cd /tmp/autoblob && \
    pip install --no-cache-dir . && \
    cd / && rm -rf /tmp/autoblob

# Copy requirements first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install libmatch in development mode
RUN pip install --no-cache-dir -e .

# Set working directory
WORKDIR /app


