# HoneyVault: Deception-Driven Encryption with HE + DTE + Sinkhole

HoneyVault is a research-oriented security platform that turns encryption into both protection and detection.

Instead of returning obvious decryption failure on wrong passwords, HoneyVault returns plausible decoy credentials. Those credentials are validated against a controlled sinkhole that logs attacker behavior, supports integrity checks, and emits runtime metrics.

## Why this project exists

Traditional encryption leaks a practical guessing signal:

- Correct password gives meaningful plaintext
- Wrong password gives garbage

That makes offline brute-force attacks easier. HoneyVault disrupts this by making wrong decryptions plausible and observable.

## Core idea

- Honey Encryption behavior for plausible wrong-decryption outcomes
- DTE-style probabilistic decoy generation for realistic cloud-secret artifacts
- Sinkhole validation architecture to trap and observe credential checks
- Tamper-evident hash-chain logs for forensic integrity
- Runtime SLO and error-budget observability

## Current capabilities

- FastAPI backend for encrypt, decrypt, sinkhole, readiness, and metrics endpoints
- MongoDB-backed vault and telemetry storage
- Memory-hard password derivation using scrypt with per-vault salt
- Stateful sinkhole decoy progression (lure levels)
- Rate limiting on sensitive endpoints (decrypt and sinkhole)
- Role-scoped metrics access (admin and service tokens)
- Streamlit dashboard with security metrics
- Benchmark and chaos benchmark attack simulation scripts
- Dockerized API and dashboard with compose orchestration

## Repository structure

- app: API, core security logic, services, DB integration
- attacker: attacker simulation, benchmark, chaos benchmark
- dashboard: Streamlit monitoring UI
- data: sample assets

## Tech stack

- Python 3.11+ (tested on 3.12)
- FastAPI + Uvicorn
- MongoDB + Motor
- Pydantic v2
- Cryptography (Fernet)
- Streamlit + Pandas

## Quick start

### 1. Clone

git clone <your-repo-url>
cd HoneyVault

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

Ensure MongoDB is running at `mongodb://localhost:27017`.

### 5. Configure environment

Create a `.env` file in the project root:

APP_ENV=development
SECRET_KEY=change-this-in-real-deployments
ADMIN_API_TOKEN=change-admin-token
SERVICE_API_TOKEN=change-service-token
METRICS_AUTH_ENABLED=true
SLO_AVAILABILITY_TARGET=0.995
MONGO_URI=mongodb://localhost:27017
FAKE_KEY_COUNT=50
KDF_N=16384
KDF_R=8
KDF_P=1
KDF_DKLEN=32
RATE_LIMIT_WINDOW_SECONDS=60
SINKHOLE_RATE_LIMIT=120
DECRYPT_RATE_LIMIT=30

### 6. Run API

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

- Docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/health
- Ready: http://127.0.0.1:8000/ready

### 7. Run dashboard

In another terminal:

streamlit run dashboard/dashboard.py

- Dashboard URL: http://localhost:8501

### 8. Run attacker simulation and benchmarks

python attacker/attacker.py
python attacker/benchmark.py
python attacker/chaos_benchmark.py

## Docker deployment

### Build and run full stack

Set secrets first (PowerShell):

$env:SECRET_KEY="replace-me"
$env:ADMIN_API_TOKEN="replace-admin-token"
$env:SERVICE_API_TOKEN="replace-service-token"

Run compose:

docker compose up --build

Services:

- API: http://127.0.0.1:8000
- Dashboard: http://127.0.0.1:8501

## API overview

### Encrypt vault

- Method: POST
- Path: `/api/encrypt`
- Body:

{
"password": "secure12345",
"aws_api_key": "AKIAREALKEY12345678"
}

### Decrypt vault

- Method: POST
- Path: `/api/decrypt`
- Body (vault id mode):

{
"password": "candidate-password",
"vault_id": "<mongo-object-id>"
}

Notes:

- Exactly one of `vault_id` or `vault` must be provided
- Response status is `real` or `fake`
- Endpoint is rate-limited

### Sinkhole endpoints

- GET `/api/cloud/instances`
- GET `/api/storage/buckets`
- POST `/api/cloud/start-instance`

Header required:

- `x-api-key: <candidate key>`

Behavior:

- Honey keys receive decoy responses with lure progression
- Non-honey keys receive real-path simulated responses
- Invalid key formats return HTTP 401

### Metrics and integrity endpoints

- GET `/api/metrics/summary` (admin)
- GET `/api/metrics/integrity` (admin)
- GET `/api/metrics/slo` (admin)
- GET `/api/metrics/prometheus` (admin or service)

Auth headers:

- Admin: `x-api-token: <ADMIN_API_TOKEN>` (legacy `x-admin-token` still supported)
- Service: `x-api-token: <SERVICE_API_TOKEN>` (prometheus endpoint)

## Security and reliability metrics

- Indistinguishability proxy
- Detection latency
- Dwell time
- Session risk scoring
- Log-chain integrity verification
- Availability and error budget remaining
- Latency and status-code buckets

## Limitations

- Strong research platform, but not a full multi-tenant enterprise product
- Indistinguishability is a practical proxy, not a formal proof
- In-memory rate limiting should be replaced with distributed counters at scale

## Roadmap

- Stronger formal modeling for DTE behavior
- Distributed rate limiting and key management integration
- Multi-tenant RBAC and policy controls
- Expanded chaos/failure testing scenarios

## License

Add your preferred license here before public release.

## Acknowledgment

Inspired by Honey Encryption research and modern cyber deception architecture.
