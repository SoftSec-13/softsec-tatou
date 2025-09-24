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

## Using Private GitHub Repositories in Docker

This project uses a private GitHub repository as a dependency. To build the Docker image successfully, you must provide a GitHub Personal Access Token (PAT) with access to the required repository.

### Steps

1. **Create a Fine-Grained GitHub PAT**
   - Go to GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens
   - Select the organization and restrict access to only the required repository
   - Grant the minimum permissions needed (usually `Contents: Read`)
   - Copy the token

2. **Create a `.env` file in the project root**
   ```env
   GITHUB_TOKEN=your_token_here
   MARIADB_ROOT_PASSWORD=your_root_password
   MARIADB_USER=your_user
   MARIADB_PASSWORD=your_password
   ```

3. **Build the Docker image**
   ```sh
   docker-compose build
   ```

The build process will use the token only for the specified repository, following GitHub's fine-grained token permissions.

## Server Key Files

The server requires two key files: `server_priv.asc` and `server_pub.asc`.

These files are **not included in the repository** for security reasons. You must create or provide them before running the server locally or in Docker.

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
