#!/bin/bash

# Stop and start the Docker db service
docker compose down -v db
docker compose up -d db
# Set environment variables
export DB_HOST=127.0.0.1
export DB_USER=tatou
export DB_PASSWORD=tatou
export DB_NAME=tatou
export TOKEN_TTL_SECONDS=3600
