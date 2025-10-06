FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TATOU_TEST_DISABLE_RMAP=1

# Install atheris dependencies and git
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything first
COPY . .

# Install runtime dependencies with authentication
ARG GITHUB_TOKEN
RUN pip install --no-cache-dir --upgrade pip && \
    if [ -n "$GITHUB_TOKEN" ]; then \
        echo "Setting up git authentication..." && \
        git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/" && \
        git config --global --list | grep url || echo "Git config not set"; \
    else \
        echo "GITHUB_TOKEN not provided"; \
    fi && \
    pip install --no-cache-dir -e . && \
    pip install --no-cache-dir -r fuzz/requirements.txt

CMD ["sleep", "infinity"]
