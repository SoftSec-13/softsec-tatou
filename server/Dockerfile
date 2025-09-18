# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install git for pip to clone repositories
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies with authentication
ARG GITHUB_TOKEN
RUN if [ -n "$GITHUB_TOKEN" ]; then \
        git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"; \
    fi && \
    pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src
COPY flag /app/flag

# Copy PGP keys for RMAP authentication
COPY src/server_priv.asc /app/server_priv.asc
COPY src/server_pub.asc /app/server_pub.asc
COPY src/public-keys/ /app/public-keys/

RUN pip install --no-cache-dir -e .

EXPOSE 5000

# Default command runs the web server
CMD ["gunicorn", "-b", "0.0.0.0:5000", "server:app", "--access-logfile=-", "--error-logfile=-", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\" %(L)s"]
