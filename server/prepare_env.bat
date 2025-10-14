@echo off
REM Stop and start the Docker db service
docker compose down -v db
docker compose up -d db

REM Set environment variables
set DB_HOST=127.0.0.1
set DB_USER=tatou
set DB_PASSWORD=tatou
set DB_NAME=tatou
set TOKEN_TTL_SECONDS=3600
