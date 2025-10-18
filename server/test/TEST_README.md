# Tatou - Testing
This document explains the structure and operation of Tatou's test suite, composed of unit tests and integration tests.

## Instructions

### Structure of the test suite

The test suite is written using the pytest framework and is composed of 42 tests spread across different files. It designed to set up the environment automatically, load and execute all necessary files. All test files are contained in the server/test folder.

The `test_api.py` script performs integration testing for Tatou and requires a database connection. This is done automatically by a configuration script called upon load. The `test_watermarking_all_methods.py` and `test_watermarking_utilities.py` files contain unit tests for the watermarking functions and can be ran without setting up the database.

The `unittest_structural_overlay_watermark.py` file is a manual test used during development to test the specific watermarking method and is not part of the pytest test suite, however it is helpful to run before the other tests (see below).

The `test_fuzzing_regression.py` file implements 10 additional tests related to specific bugs discovered during fuzzing and was not developed as part of the original testing suite. It will, however, be run when pytest is called on the whole test suite. See the `tatou/server/fuzz` folder for complete documentation.

To see how the tests are mapped to the API's specification, see `API_TEST_SPECIFICATIONS.md`

### Configure and run the test suite

Tatou's test suite needs a preparation shell script to be run before the tests are executed. This is done automatically by the test suite. Depending on your OS, you may need to select a different script. Open the `test_api.py` module and navigate to this section (lines 20-26):

```python
#Run environment preparation file
print("Preparing the environment...")
script_dir = Path(__file__).parent
env_script = script_dir / "prepare_env.sh"
result = subprocess.run(str(env_script.resolve()), shell=True)
print("Waiting for db to be ready...")
sleep(10)
```

Choose between `"prepare_env.bat"` and`"prepare_env.sh"` depending on whether you are running Windows or Linux. Both files are already included in the project. The test suite was developed on a Windows machine.

You may also want to change the duration of the sleep function, depending on your machine's processing speed.

The test suite also requires a file named `input.pdf` under `test/storage/files/username`, and a file named `watermarked.pdf` in the same location, watermarked with the Structural and Overlay method. To achieve this, place a PDF file of your choice in the folder (it should not be bigger than 50 Mb), then run `unittest_structural_overlay_watermark.py` once to create the watermarked version (make sure you have installed the necessary dependencies, see below).

The RMAP protocol is based on public/private key authentication. You will need your pair of keys for the server as explained in `tatou/README.md`, and you will also need two extra keys to simulate a test entity when running the tests. The keys used for this purpose don't pose a security issue and are already provided in the repository. However, before running, you will need to set up the private keys' passwords in your `.env` file as follows:

```.env
PRIVKEY_PASSPHRASE=yourpassword
TEST_PASSPHRASE=testingtatou
```

When you are all set, run the following:

```bash
cd tatou/server

# Create a python virtual environement [optional]
python3 -m venv .venv

# Activate your virtual environement [optional]
. .venv/bin/activate

# Install the necessary dependencies
python -m pip install -e ".[dev]"

# Run all the tests
python -m pytest /test

# Run a specific test file
python -m pytest /test/<filename>.py

# See verbose output and output of print functions
python -m pytest -s -vv /test

# Perform coverage testing (you may need to install the cov plugin for pytest)
python -m pytest --cov=src /test
```
