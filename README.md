# The Hinderman

The Hinderman is a local-first AI security gateway prototype. It places a policy and inspection layer between users and an LLM: prompts and image OCR text are screened before model invocation, model responses are checked before returning, RAG retrieval is access-controlled, and audit events avoid storing raw prompt/OCR content.

The default local model is Ollama `qwen3.5:4b`. The gateway also supports deterministic stub mode for development and automated tests.

> **Prototype notice:** This is a demonstration project, not a certified DLP, identity, or production security product. Demo users and the default signing secret are not suitable for an exposed or production deployment.

## Features

- FastAPI gateway with typed request/response contracts and editable YAML policies.
- PII and credential detection, including Aadhaar, PAN, payment cards, contact details, passwords, and common API keys.
- Prompt-injection scanning with normalization for common homoglyphs, leetspeak, zero-width characters, and selected Base64-encoded instructions.
- Policy actions: `allow`, `warn`, `mask`, `redact`, `block`, and `require_approval`.
- Optional role-, department-, and clearance-filtered retrieval over seeded synthetic documents.
- PNG/JPEG image input in Secure Chat: up to three images, at most 5 MB each. Tesseract OCR text is screened with the prompt; image bytes are not sent to the LLM. The dashboard displays previews and allows removal before sending.
- Canary-response detection and privacy-safe, hash-chained audit events.
- React/Vite dashboard for secure chat, image uploads, incidents, metrics, approvals, and policy editing.

## Requirements

- Python 3.11 or newer.
- Node.js and npm, for building or running the dashboard.
- Ollama and the configured model for live local LLM responses.
- Tesseract OCR for image requests. The Docker gateway image installs it; native Windows runs need Tesseract installed separately.
- Docker Desktop with its Linux container engine, if using Compose.

## Quick start: Windows native

From the repository root in PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

Push-Location dashboard
npm.cmd install
npm.cmd run build
Pop-Location

.\scripts\start.ps1
```

The start script launches the API and serves the built dashboard:

- Dashboard: <http://localhost:5173>
- API: <http://localhost:8000>
- OpenAPI docs: <http://localhost:8000/docs>
- Health: <http://localhost:8000/health>

Stop native services with:

```powershell
.\scripts\stop.ps1
```

The script expects Ollama to be reachable at `http://localhost:11434` and Tesseract to be installed. Runtime logs and process information are written under `data\runtime` (ignored by Git).

To run the API manually for development, install the Python requirements as above and use:

```powershell
$env:LLM_MODE = "stub"  # or "ollama"
$env:OCR_MODE = "stub"  # use "tesseract" when Tesseract is installed
python -m uvicorn gateway.main:app --reload
```

Run the dashboard dev server in a second terminal:

```powershell
Set-Location dashboard
npm.cmd install
npm.cmd run dev
```

The development dashboard is at <http://localhost:5173>. Set `VITE_API_URL` at dashboard build/dev time if the API is not at `http://localhost:8000`.

## Quick start: Docker Compose

Ensure Docker Desktop is using Linux containers and Ollama is running on the host with the configured model available:

```powershell
ollama pull qwen3.5:4b
docker compose up --build
```

Compose exposes the dashboard at <http://localhost:3000>, the API at <http://localhost:8000>, and API docs at <http://localhost:8000/docs>. The gateway connects to host Ollama through `http://host.docker.internal:11434`, installs Tesseract in its image, and persists audit data in the `gateway-data` Docker volume.

Stop the services and remove the Compose network (retaining the named audit volume):

```powershell
docker compose down
```

To delete the audit volume as well, use `docker compose down --volumes`; this permanently removes the persisted local audit database.

If Docker Desktop cannot read a workspace located in a protected or synchronized folder (for example, a OneDrive path), move/clone the repository to a Docker-shared local directory, or stage the source in an accessible local directory and run Compose with that directory's `docker-compose.yml`. Do not include `.git`, virtual environments, dependency folders, or generated build output in the staged context.

To use the deterministic adapter without Ollama:

```powershell
$env:LLM_MODE = "stub"
docker compose up --build
```

Compose environment variables may be set in the shell or in an untracked `.env` file in the Compose directory. Supported settings include:

| Variable | Default | Purpose |
|---|---|---|
| `LLM_MODE` | `ollama` | `ollama` for the host Ollama service or `stub` for deterministic local responses |
| `LLM_MODEL` | `ollama/qwen3.5:4b` | Model configured for the gateway |
| `OLLAMA_API_BASE` | `http://host.docker.internal:11434` in Compose | Ollama API base URL |
| `LLM_TIMEOUT_SECONDS` | `180` | LLM request timeout |
| `LLM_MAX_TOKENS` | `256` | Maximum generated tokens |
| `OLLAMA_THINK` | `false` | Enable/disable Ollama thinking mode |
| `OCR_MODE` | `tesseract` in Compose; `stub` in the OCR module | OCR mode; stub deliberately rejects image requests |
| `TESSERACT_CMD` | detected executable | Optional explicit Tesseract executable path |
| `JWT_SECRET` | local-demo value in Compose | JWT signing secret; replace before any non-demo deployment |
| `AUDIT_DB` | `data/audit.sqlite3` natively; `/data/audit.sqlite3` in Compose | SQLite audit database path |
| `POLICY_FILE` | `gateway/policy/policies.yaml` | Policy YAML path |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Comma-separated allowed dashboard origins |
| `VITE_API_URL` | `http://localhost:8000` | Dashboard API URL, applied at frontend build time |

## Demo accounts

| Username | Password | Role | Department |
|---|---|---|---|
| `intern` | `intern-demo` | intern | engineering |
| `hr` | `hr-demo` | hr | hr |
| `finance` | `finance-demo` | finance | finance |
| `admin` | `admin-demo` | administrator | security |

These fixed accounts are for local demonstration only. Authentication currently uses the seeded in-code identities; replace them with managed identities and secure credential provisioning before deployment beyond a trusted local demo. Set a unique, strong `JWT_SECRET` and protect the API and audit storage.

## Using Secure Chat and image input

1. Sign in to the dashboard and open **Secure chat**.
2. Enter a prompt, or attach an image without a prompt (the dashboard supplies a short inspection prompt).
3. Choose **Add image** and select up to three PNG or JPEG files, each no larger than 5 MB.
4. Review the previews and remove any attachment you do not want to send.
5. Select **Send securely**. The gateway decodes and normalizes each image, extracts text with Tesseract, and applies the same inbound PII/injection checks to the OCR text and typed prompt.

Unsupported image types, invalid image data, excessive dimensions, OCR failures, and OCR timeouts fail closed. OCR text and image bytes are not intentionally included in audit snippets; audit events retain a redacted prompt snippet and content digest. The gateway does not send image bytes to the model.

## API

All endpoints other than login and health require a bearer token. Obtain one with:

```powershell
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/auth/login `
  -ContentType "application/json" `
  -Body '{"username":"intern","password":"intern-demo"}'
$token = $login.access_token
$headers = @{ Authorization = "Bearer $token" }
```

Send a chat request:

```powershell
$body = @{
  prompt = "Summarise this note and protect its personal data."
  use_rag = $false
  attachments = @()
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8000/v1/chat `
  -Headers $headers -ContentType "application/json" -Body $body
```

`attachments` accepts objects with `kind: "image"`, `mime: "image/png"` or `"image/jpeg"`, and `data_b64` containing the Base64-encoded image bytes. The request contract allows up to three image attachments.

| Method and path | Purpose |
|---|---|
| `GET /health` | Gateway and configured LLM readiness |
| `POST /api/auth/login` | Exchange a demo username/password for a JWT |
| `POST /v1/chat` | Inspect a prompt, optional image attachments, and optional RAG request |
| `GET /api/users` | List demo identities (authenticated) |
| `GET /api/documents` | List documents accessible to the current user |
| `GET /api/policies` | Read active policy configuration |
| `PUT /api/policies` | Replace policy configuration (administrator only) |
| `GET /api/incidents?limit=100` | Read privacy-safe audit events |
| `GET /api/incidents/verify` | Verify the audit hash chain |
| `GET /api/metrics/summary` | Summary of recent actions and findings |
| `GET /api/metrics/trends` | Incident counts over time |
| `GET /api/approvals` | Read approval queue (administrator only) |
| `POST /api/approvals/{id}/decision` | Approve/reject a pending request (administrator only) |

The interactive API reference is available at `/docs`.

## Security and privacy notes

- The gateway screens inbound content before calling the LLM and screens model output before returning it.
- Typed prompt PII and secrets are masked according to `gateway/policy/policies.yaml`. Blocked and approval-required prompts do not proceed to model completion.
- RAG retrieval filters documents by role, department, and clearance. Denied document identifiers may be reported without disclosing restricted document contents.
- Image text is extracted locally by Tesseract in the gateway container and inspected alongside typed prompt text. Image data is never passed to the LLM.
- Audit events store a SHA-256 content digest and a redacted snippet, not the raw prompt/OCR text, and form a verifiable hash chain.
- Injection checks are rule-based. The optional transformer classifier is not downloaded automatically; the rule-based detector is the baseline in this project.
- A synthetic evaluation set is useful for regression checks but cannot establish security against unknown or adaptive attacks.
- Demo credentials, the default JWT signing secret, local HTTP endpoints, and local storage make this an educational/local prototype. Do not expose it to a network without a security review and deployment hardening.

## Tests and evaluation

Install project dependencies, then run the complete Python suite:

```powershell
python -m pytest -q
```

Run the 60-case gateway acceptance matrix and the additional 50-case edge suite as part of the full test run. The edge suite covers detector boundaries, injection normalization and benign lookalikes, image decoding/limits, and request validation.

Run the labelled synthetic evaluation:

```powershell
python -m eval.run_eval
```

Evaluation metrics (precision, recall, F1, false-positive rate, and counts) are measurements over the checked-in synthetic dataset, not a guarantee for other inputs. OCR integration tests use real Tesseract when available and are skipped when it is not installed.

Build/type-check the dashboard:

```powershell
Set-Location dashboard
npm.cmd install
npm.cmd run build
```

The optional Chroma retrieval backend can be installed and populated with:

```powershell
python -m pip install -r requirements-rag.txt
$env:RAG_BACKEND = "chroma"
python -m rag.ingest
```

The default keyword retriever requires no embedding-model download.

## Repository layout

```text
contracts/       Pydantic request, response, user, and audit contracts
detectors/       PII, credential, and confidential-content inspection
eval/            Labelled evaluation data and metrics runner
gateway/         FastAPI routes, chat pipeline, policies, audit, and LLM adapter
injection/       Prompt/document injection rules and image OCR wrapper
rag/             Synthetic documents and permission-filtered retrieval
dashboard/       React/Vite chat, image upload, incidents, approvals, and policies
scripts/         Native Windows start/stop scripts
tests/           Unit, API integration, acceptance, and edge-case tests
docker-compose.yml
Dockerfile
```
