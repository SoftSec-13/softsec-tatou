#!/bin/bash

#You can make this file into a shell file
#To test the API
    docker compose down -v db
    docker compose up -d db

    #linux
    export DB_HOST=127.0.0.1
    export DB_USER=tatou
    export DB_PASSWORD=tatou
    export DB_NAME=tatou
    export TOKEN_TTL_SECONDS=3600

    #windows
    set DB_HOST=127.0.0.1
    set DB_USER=tatou
    set DB_PASSWORD=tatou
    set DB_NAME=tatou
    set TOKEN_TTL_SECONDS=3600

    sleep 5
    python -m pytest -vv test_api.py

#All else
    python -m pytest -vv <test_file_name>

#Run all tests: on Windows: .\run_tests.bat

Mutation: mutmut run --runner "run_tests.bat"
