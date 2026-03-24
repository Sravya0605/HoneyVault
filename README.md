# HoneyVault: Deception-Driven Encryption with HE + DTE + Sinkhole

HoneyVault is a research-oriented MVP that turns encryption from passive protection into an active detection sensor.

Instead of returning obvious failure on wrong passwords, it uses Honey Encryption behavior with a Distribution-Transforming Encoder (DTE)-style decoy generator so wrong decryptions still produce plausible cloud credentials. Those decoy credentials are then validated inside a controlled sinkhole service that looks realistic to attackers and produces telemetry for detection.

## Why this project exists

Traditional encryption leaks a practical guessing signal:

- Correct password gives meaningful plaintext
- Wrong password gives garbage

That enables offline brute-force workflows against weak passwords.

HoneyVault disrupts this by making wrong decryptions appear plausible, forcing attackers into a costly validation loop while defenders gain high-value behavioral logs.

## Core idea (unchanged)

- Honey Encryption behavior for plausible wrong-decryption outcomes
- DTE-style probabilistic decoy generation for realistic cloud-secret artifacts
- Validation sinkhole architecture to trap and observe credential verification attempts

## What this MVP currently delivers

- FastAPI backend for encrypt, decrypt, and sinkhole endpoints
- Vault storage in MongoDB
- Memory-hard password derivation using scrypt with per-vault salt
- DTE-style fake secret sampling (API key plus contextual attributes)
- Sinkhole telemetry including fake vs real interaction classification
- Streamlit dashboard with research-facing metrics:
	- Indistinguishability proxy
	- Dwell time
	- Detection latency
- Attacker simulation scripts for brute-force and key validation workflow

## Repository structure

- app: API, security core, services, database integration
- attacker: attack simulation tooling
- dashboard: Streamlit monitoring interface
- data: sample vault and password files

## Tech stack

- Python 3.11+ (works with 3.12)
- FastAPI + Uvicorn
- MongoDB
- Pydantic
- Cryptography (Fernet)
- Streamlit + Pandas

## Quick start

### 1. Clone

		git clone <your-repo-url>
		cd MP_HE

### 2. Create virtual environment

Windows PowerShell:

		py -3.12 -m venv venv
		.\venv\Scripts\Activate.ps1

Linux or macOS:

		python3 -m venv venv
		source venv/bin/activate

### 3. Install dependencies

		pip install -r requirements.txt

### 4. Start MongoDB

Ensure MongoDB is running locally at mongodb://localhost:27017

If using Docker for MongoDB only:

		docker run -d --name honeyvault-mongo -p 27017:27017 mongo:7

### 5. Configure environment

Create a .env file in the project root:

		SECRET_KEY=change-this-in-real-deployments
		MONGO_URI=mongodb://localhost:27017
		FAKE_KEY_COUNT=7
		KDF_N=16384
		KDF_R=8
		KDF_P=1
		KDF_DKLEN=32

### 6. Run backend API

		uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

API docs:

- http://127.0.0.1:8000/docs

### 7. Run dashboard

In a second terminal:

		streamlit run dashboard/dashboard.py

Dashboard URL:

- http://localhost:8501

### 8. Run attacker simulation (optional demo)

In a third terminal:

		cd attacker
		python attacker.py

## API overview

### Encrypt vault

- Method: POST
- Path: /api/encrypt
- Body:

		{
			"password": "secure123",
			"aws_api_key": "AKIAREALKEY12345678"
		}

### Decrypt vault

- Method: POST
- Path: /api/decrypt
- Body:

		{
			"password": "candidate-password",
			"vault": { ... }
		}

Response status is either real or fake, and both can look plausible to an attacker.

### Sinkhole endpoints

- GET /api/cloud/instances
- GET /api/storage/buckets
- POST /api/cloud/start-instance

Header required:

- x-api-key: <candidate key>

## Research metrics included

- Indistinguishability proxy:
	Balance-based proxy showing how difficult it is to separate fake vs real interactions using simple output ratios.
- Dwell time:
	Time span attackers remain engaged with fake credentials.
- Detection latency:
	Time from first observed event to first fake-key interaction detection.

## Deployment options

### Option A: Single VM (simple MVP deployment)

1. Provision Ubuntu VM
2. Install Python, MongoDB, Nginx
3. Copy project and install requirements
4. Run API with systemd + Uvicorn
5. Reverse proxy with Nginx
6. Run Streamlit as separate systemd service

### Option B: Containerized deployment

Use one container for API and one for dashboard, with managed MongoDB.

Suggested production improvements before final deployment:

- Restrict CORS
- Rotate secret management to vault service
- Add auth for dashboard
- Add rate controls and API gateway
- Add persistent monitoring stack (Prometheus/Grafana or equivalent)

## MVP submission notes (for competitions)

To maximize judging outcomes, focus your demo on this attack-defender story:

1. Show stolen vault and offline brute-force workflow
2. Show multiple plausible decrypted keys from wrong attempts
3. Show attacker validating keys against sinkhole
4. Show live telemetry in dashboard
5. Report the three research metrics from your run

## Limitations (honest)

- This is a strong research MVP, not a finalized production security platform
- Indistinguishability metric is currently a practical proxy, not a formal proof
- Sinkhole realism can be further expanded with deeper stateful cloud simulation

## Roadmap

- More rigorous DTE modeling and calibration from empirical credential datasets
- Automated experiment runner with repeatable seeds and statistical confidence intervals
- Test suite with integration and adversarial benchmarks
- Better multi-tenant deployment and policy controls

## License

Add your preferred license here before public release.

## Acknowledgment

This project is inspired by Honey Encryption research and modern cyber deception architecture patterns.
