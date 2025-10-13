# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/nharrand/tatou.git
```

Note that you should probably for the repo and clone your own repo.

### Run python unit tests

```bash
cd tatou/server

# Create a python virtual environement
python3 -m venv .venv

# Activate your virtual environement
. .venv/bin/activate

# Install the necessary dependencies
python -m pip install -e ".[dev]"

# Run the unit tests
python -m pytest
```

### Enable pre-commit
```bash
# Activate your virtual environement
. .venv/bin/activate
# Install pre-commit
pre-commit install
```

### Deploy

From the root of the directory:

```bash
# Create a file to set environement variables like passwords.
cp sample.env .env

# Edit .env and pick the passwords you want

# Rebuild the docker image and deploy the containers
docker compose up --build -d

# Monitor logs in realtime
docker compose logs -f

# Test if the API is up
http -v :5000/healthz

# Open your browser at 127.0.0.1:5000 to check if the website is up.
```

### Deploy on production (VM)
```bash
cd softsec-tatou

# Create .env and fill with secrets
vim .env

# Deploy the containers
sudo docker compose -f docker-compose.prod.yml up -d
```

### Monitor

1. Open localhost:3000
2. Login with admin:admin
3. To view Dashboards, go to Home->Dashboards->Flask Gunicorn Logs & Metrics



## Environment Setup

To run or build the project, you need to set up environment variables in a `.env` file at the project root. You can use the provided `.env.sample` as a template:

```sh
cp .env.sample .env
```

Edit `.env` and fill in the required values:

- `MARIADB_ROOT_PASSWORD`: Root password for MariaDB
- `MARIADB_USER`: Database user (default: tatou)
- `MARIADB_PASSWORD`: Database password (default: tatou)
- `SECRET_KEY`: Flask secret key
- `GITHUB_TOKEN`: GitHub token for accessing private dependencies during Docker builds (required)
- `DOCKERHUB_USER`: Prod only, access to container registry
- `DOCKERHUB_PASSWORD`: Prod only, access to container registry
- `PRIVKEY_PASSPHRASE`: The passphrase for the private key

Example `.env.sample`:
```
MARIADB_ROOT_PASSWORD=your_root_password
MARIADB_USER=tatou
MARIADB_PASSWORD=tatou
SECRET_KEY=flask-key
GITHUB_TOKEN=your_github_token_here

#For production, required:
DOCKERHUB_USER=your_dockerhub_username
DOCKERHUB_PASSWORD=your_dockerhub_password
PRIVKEY_PASSPHRASE=priv key passprase
```

Since private dependencies are used, you must provide a valid GitHub Personal Access Token that allows read access to https://github.com/SoftSec-13/RMAP-Server as `GITHUB_TOKEN` in your `.env` and as a secret in your repository settings. The workflow will pass this as a build argument to Docker.

## Other Dependencies

- MariaDB (database)
- Python 3.12
- Git (for installing dependencies from GitHub)
- Any other environment variables required by your application can be added to `.env.sample` and `.env` as needed.

## Server Key Files

The server requires two key files: `server_priv.asc` and `server_pub.asc` in `server/src/`. These are not included in the repository for security reasons. Generate or provide them before running the server or Docker Compose.

Place your key files in `server/src/` as follows:

- `server/src/server_priv.asc`
- `server/src/server_pub.asc`

If you do not have these files, you can generate them using GPG or another key generation tool. Example (GPG):

```sh
gpg --full-generate-key
# Export the private key
gpg --export-secret-keys --armor <KEY_ID> > server/src/server_priv.asc
# Export the public key
gpg --export --armor <KEY_ID> > server/src/server_pub.asc
```

Make sure these files exist before starting the server or running Docker Compose.
