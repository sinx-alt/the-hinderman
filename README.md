# The Hinderman — AI Security Gateway

A local-first gateway that inspects prompts and model responses, applies editable security policies, restricts document retrieval by user access, and records privacy-safe audit events. Ollama with `qwen3.5:4b` is the default model; stub mode remains available for offline development and tests.

## Quick start (Python)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn gateway.main:app --reload
```

For the complete local Ollama + dashboard prototype, build the dashboard once and launch both services with the included PowerShell scripts:

```powershell
cd dashboard
npm install
npm run build
cd ..
.\scripts\start.ps1
```

Open `http://localhost:5173`; API docs are at `http://localhost:8000/docs`. Stop both local services with `.\scripts\stop.ps1`. Runtime logs and process IDs are saved under the ignored `data\runtime` directory.

Open `http://localhost:8000/docs` for the API and `http://localhost:8000/health` for readiness. For the dashboard, use the Docker Compose instructions below or run the Vite app in `dashboard/`.

## Quick start (Docker)

```powershell
docker compose up --build
```

The dashboard is at `http://localhost:3000`; the API and OpenAPI UI are at `http://localhost:8000` and `http://localhost:8000/docs`. Compose defaults to `LLM_MODE=ollama`, `LLM_MODEL=ollama/qwen3.5:4b`, and connects to Ollama on the Windows host at port 11434. Persistent local audit data is stored in the `gateway-data` volume. To run without Ollama, set `LLM_MODE=stub`.

## Demo accounts

| Username | Password | Role | Department |
|---|---|---|---|
| `intern` | `intern-demo` | intern | engineering |
| `hr` | `hr-demo` | hr_officer | hr |
| `finance` | `finance-demo` | finance_manager | finance |
| `admin` | `admin-demo` | admin | security |

These seeded credentials are for local demonstrations only. Set `JWT_SECRET` and replace demo users before exposing the service to a network.

## Enable Ollama

Ollama with `qwen3.5:4b` is configured by default. Verify it is available with `ollama list`; the gateway connects to `http://localhost:11434` when run directly and `http://host.docker.internal:11434` from Compose. Set `LLM_MODEL`, `OLLAMA_API_BASE`, or `LLM_MAX_TOKENS` to override defaults. Ollama's native chat API is used by default; optionally install `requirements-llm.txt` to use LiteLLM. Stub mode (`LLM_MODE=stub`) is deterministic and keeps the gateway testable without Ollama.

## API

- `POST /api/auth/login` — exchange demo credentials for a JWT.
- `POST /v1/chat` — inspect prompt, optional attachments and access-controlled RAG, then return response and gateway report.
- `GET /api/policies` / `PUT /api/policies` — read or replace the YAML policy configuration (admin only for writes).
- `GET /api/incidents`, `/api/metrics/summary`, `/api/metrics/trends` — privacy-safe audit and metrics.
- `GET /api/approvals`, `POST /api/approvals/{id}/decision` — approval queue.
- `GET /api/users` and `GET /api/documents` — demo identity and accessible document metadata.

Pass the JWT as `Authorization: Bearer <token>`. The login response includes a token for the dashboard.

Example:

```json
{
  "prompt": "Summarise this: Rahul, Aadhaar 2345 6789 0123, PAN ABCDE1234F",
  "use_rag": false,
  "attachments": []
}
```

The Aadhaar/PAN are replaced with placeholders before the LLM adapter receives the prompt. Audit events retain a SHA-256 digest and redacted snippet, not the original prompt or OCR text.

## Security behavior

- PII and credentials are inspected before model invocation; prompt-injection rules can block extraction attempts.
- Policies in `gateway/policy/policies.yaml` hot-reload when edited. Actions include `allow`, `warn`, `mask`, `redact`, `block`, and `require_approval`.
- RAG filters documents by role, department, and clearance before retrieval. Unauthorized matching documents are counted without exposing their contents.
- Image attachments accept PNG/JPEG only, at most three and 5 MB decoded each. Pillow re-encodes each image to PNG to strip metadata. Tesseract OCR text is then inspected exactly like typed text; image bytes are never sent to the model. Any decode, OCR, or OCR timeout error denies the request. In `OCR_MODE=stub`, image requests deliberately fail closed.
- Audit rows form a SHA-256 hash chain. `GET /api/incidents/verify` reports whether the chain verifies.
- The rule-based injection detector is the always-available baseline. The optional transformer classifier is intentionally not downloaded automatically.

## Development and evaluation

```powershell
python -m pytest
python -m eval.run_eval
```

The labelled JSONL evaluation set has benign, PII, direct/indirect injection, RAG, and benign-lookalike cases. The evaluation command reports precision, recall, F1, false-positive rate, and confusion counts. Results are measurements on this small synthetic set, not a guarantee against all attacks. OCR stub mode is used in CI; install Tesseract and set `OCR_MODE=tesseract` to measure actual OCR locally. Optional vector retrieval is available with `pip install -r requirements-rag.txt`, `RAG_BACKEND=chroma`, then `python -m rag.ingest`; the default keyword retriever needs no embedding model download.

```powershell
cd dashboard
npm install
npm run dev
```

The gateway API is the source of truth. Dashboard API requests default to `http://localhost:8000` and can be configured with `VITE_API_URL`.

## Project layout

```text
contracts/       Shared Pydantic v1.2 contracts
gateway/         FastAPI endpoints, pipeline, policy engine, actions, LLM adapter
detectors/       PII, credential, and confidential-content inspection
injection/       Prompt and document injection scoring; fail-closed OCR wrapper
rag/             Synthetic documents and permission-filtered retrieval
eval/            60 labelled prompts and metrics runner
dashboard/       React/Vite chat, incidents, approvals, policy editor
tests/           Unit and API integration tests
```

This is a demonstration security gateway, not a certified DLP product. Review and adapt policies, secrets, account provisioning, and storage before production use.
