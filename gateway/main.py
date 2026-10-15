from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from contracts import ChatRequest, UserContext
from gateway import approvals
from gateway.audit.logger import list_events, verify_chain
from gateway.auth import authenticate, create_token, get_current_user, require_admin
from gateway.pipeline import RequestDenied, process_chat
from gateway.policy.engine import PolicyEngine, PolicyDocument
from rag.retriever import accessible_documents

POLICY_PATH = Path(os.getenv("POLICY_FILE", Path(__file__).parent / "policy" / "policies.yaml"))
policies = PolicyEngine(POLICY_PATH)
app = FastAPI(title="The Hinderman AI Security Gateway", version="1.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class ApprovalDecision(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")


@app.get("/health")
async def health() -> dict[str, Any]:
    mode = os.getenv("LLM_MODE", "ollama").lower()
    configured = os.getenv("LLM_MODEL", "ollama/qwen3.5:4b")
    ready = mode == "stub"
    if mode == "ollama":
        base = os.getenv("OLLAMA_API_BASE", "http://localhost:11434").rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                response = await client.get(f"{base}/api/tags")
                response.raise_for_status()
                model_name = configured.removeprefix("ollama/")
                ready = any(item["name"] == model_name for item in response.json().get("models", []))
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            ready = False
    return {
        "status": "ok",
        "version": "1.2.0",
        "llm_mode": mode,
        "configured_model": configured,
        "llm_ready": ready,
    }


@app.post("/api/auth/login")
def login(body: LoginRequest) -> dict[str, Any]:
    user = authenticate(body.username, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"access_token": create_token(user), "token_type": "bearer",
            "user": user.model_dump(mode="json")}


@app.get("/api/users")
def list_users(_: UserContext = Depends(get_current_user)) -> list[dict[str, Any]]:
    from gateway.auth import _DEMO_USERS

    return [
        {"username": username, **user.model_dump(mode="json")}
        for username, (_, user) in _DEMO_USERS.items()
    ]


@app.get("/api/documents")
def documents(user: UserContext = Depends(get_current_user)) -> list[dict[str, str]]:
    return accessible_documents(user)


@app.post("/v1/chat")
async def chat(body: ChatRequest, user: UserContext = Depends(get_current_user)) -> dict[str, Any]:
    try:
        result = await process_chat(body, user, policies)
    except RequestDenied as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@app.get("/api/policies")
def get_policies(_: UserContext = Depends(get_current_user)) -> dict[str, Any]:
    return {"policies": policies.list()}


@app.put("/api/policies")
def put_policies(body: PolicyDocument, user: UserContext = Depends(get_current_user)) -> dict[str, Any]:
    require_admin(user)
    try:
        updated = policies.replace(body.model_dump(mode="json"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"policies": updated}


@app.get("/api/incidents")
def incidents(limit: int = Query(default=100, ge=1, le=500),
              _: UserContext = Depends(get_current_user)) -> dict[str, Any]:
    return {"incidents": list_events(limit)}


@app.get("/api/incidents/verify")
def verify(_: UserContext = Depends(get_current_user)) -> dict[str, object]:
    return verify_chain()


@app.get("/api/metrics/summary")
def metrics_summary(_: UserContext = Depends(get_current_user)) -> dict[str, Any]:
    events = list_events(500)
    categories: dict[str, int] = {}
    actions: dict[str, int] = {}
    for event in events:
        actions[event["action"]] = actions.get(event["action"], 0) + 1
        for finding in event["findings"]:
            categories[finding["type"]] = categories.get(finding["type"], 0) + finding["count"]
    return {"total_incidents": len(events), "blocked_requests": actions.get("block", 0),
            "approvals_pending": sum(1 for item in approvals.list_approvals() if item["status"] == "pending"),
            "actions": actions, "categories": categories,
            "average_latency_ms": round(sum(item["latency_ms"] for item in events) / max(len(events), 1), 2)}


@app.get("/api/metrics/trends")
def metrics_trends(_: UserContext = Depends(get_current_user)) -> dict[str, Any]:
    buckets: dict[str, dict[str, int]] = {}
    for event in reversed(list_events(500)):
        day = event["ts"][:10]
        buckets.setdefault(day, {"incidents": 0, "blocked": 0})
        buckets[day]["incidents"] += 1
        buckets[day]["blocked"] += int(event["action"] == "block")
    return {"trends": [{"date": day, **values} for day, values in sorted(buckets.items())]}


@app.get("/api/approvals")
def get_approvals(user: UserContext = Depends(get_current_user)) -> dict[str, Any]:
    require_admin(user)
    return {"approvals": approvals.list_approvals()}


@app.post("/api/approvals/{approval_id}/decision")
def approval_decision(approval_id: str, body: ApprovalDecision,
                      user: UserContext = Depends(get_current_user)) -> dict[str, Any]:
    require_admin(user)
    try:
        result = approvals.decide(approval_id, body.decision, user.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return result
