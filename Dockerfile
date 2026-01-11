## -*- docker-image-name: "libmatch" -*-
FROM python:3.12-slim

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
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Patch angr balancer.py for BoolV/BoolS fix (commit a682cae not yet in PyPI release)
# This fixes: AttributeError: 'bool' object has no attribute 'cardinality'
RUN BALANCER_PATH=$(python -c "import angr; import os; print(os.path.join(os.path.dirname(angr.__file__), 'utils', 'balancer.py'))") && \
    sed -i 's/if cast(Base, truism.args\[0\]).cardinality == 1:/if truism.op in {"BoolV", "BoolS"} or cast(Base, truism.args[0]).cardinality == 1:/' "$BALANCER_PATH"

# Copy application code (including autoblob submodule contents)
COPY . .

# Install autoblob from submodule
RUN pip install --no-cache-dir -e ./autoblob

# Install libmatch in development mode
RUN pip install --no-cache-dir -e .

WORKDIR /app
