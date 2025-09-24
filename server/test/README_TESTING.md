```
Inside venv:

docker compose down -v db
docker compose up -d db

export DB_HOST=127.0.0.1
export DB_USER=tatou
export DB_PASSWORD=tatou
export DB_NAME=tatou
export TOKEN_TTL_SECONDS=3600

Wait 5 seconds for the database to init

python -m pytest test_api.py
```
