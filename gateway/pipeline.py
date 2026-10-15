from __future__ import annotations

import asyncio
import base64
import binascii
import os
import time
import uuid
from collections import Counter

from contracts import AuditFinding, ChatRequest, ChatResponse, Finding, UserContext
from detectors import inspect
from gateway.actions import summarize_findings, transform_text
from gateway.approvals import enqueue_approval
from gateway.audit.logger import log_event
from gateway.llm_adapter import CANARY_TOKEN, complete
from gateway.policy.engine import PolicyEngine
from injection.ocr import extract, normalize_image
from injection.rules import findings as injection_findings
from rag.retriever import retrieve

MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024


class RequestDenied(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _image_text(request: ChatRequest) -> tuple[str, list[Finding]]:
    if not request.attachments:
        return "", []
    if sum(1 for item in request.attachments if item.kind == "image") > 3:
        raise RequestDenied("At most three image attachments are allowed")
    texts: list[str] = []
    findings: list[Finding] = []
    for index, attachment in enumerate(request.attachments, start=1):
        try:
            image_bytes = base64.b64decode(attachment.data_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RequestDenied(f"Image {index} has invalid base64 data") from exc
        if len(image_bytes) > MAX_ATTACHMENT_BYTES:
            raise RequestDenied(f"Image {index} exceeds the 5 MB limit")
        try:
            clean_png = normalize_image(image_bytes, attachment.mime)
        except ValueError as exc:
            raise RequestDenied(f"Image {index} was denied: {exc}") from exc
        result = extract(clean_png)
        if not result.ok:
            raise RequestDenied(f"Image {index} was denied: {result.error or 'OCR failed'}")
        text = result.text.strip()
        texts.append(text)
        findings.extend(inspect(text, "prompt"))
        findings.extend(injection_findings(text, "user"))
    joined = "\n".join(texts)
    offset = len(request.prompt) + 1
    return joined, [
        item.model_copy(update={
            "start": (item.start + offset) if item.start is not None else None,
            "end": (item.end + offset) if item.end is not None else None,
        })
        for item in findings
    ]


async def process_chat(
    request: ChatRequest, user: UserContext, policies: PolicyEngine
) -> ChatResponse:
    started = time.perf_counter()
    request_id = str(uuid.uuid4())
    image_text, image_findings = _image_text(request)
    original = request.prompt + (("\n" + image_text) if image_text else "")
    pii_findings, injection = await asyncio.gather(
        asyncio.to_thread(inspect, original, "prompt", user),
        asyncio.to_thread(injection_findings, original, "user"),
    )
    inbound_findings = pii_findings + injection + image_findings
    seen: set[tuple[str, str, int | None, int | None]] = set()
    inbound_findings = [
        finding for finding in inbound_findings
        if not ((key := (finding.type, finding.category, finding.start, finding.end)) in seen or seen.add(key))
    ]
    source = "image" if image_text else "prompt"
    prompt_findings = [
        item for item in inbound_findings
        if item.start is not None and item.end is not None and item.end <= len(request.prompt)
    ]
    audit_snippet = transform_text(request.prompt, prompt_findings, "mask")
    if image_text:
        audit_snippet += " [IMAGE_ATTACHMENT_OCR_SCANNED]"
    context: list[str] = []
    retrieval = {"chunks": [], "denied_count": 0, "denied_doc_ids": []}
    if request.use_rag:
        retrieval = await asyncio.to_thread(retrieve, request.prompt, user)
        context = [f"{chunk['title']}: {chunk['text']}" for chunk in retrieval["chunks"]]
        if retrieval["denied_count"] and not retrieval["chunks"]:
            inbound_findings.append(
                Finding(category="RESTRICTED_DOC", type="RESTRICTED_DOC", start=None, end=None,
                        confidence=1.0, detector="rag_acl")
            )
    decision = policies.decide(inbound_findings, "prompt", source)
    if decision.action == "block":
        elapsed = (time.perf_counter() - started) * 1000
        event = log_event(
            user_id=user.user_id, direction="prompt",
            findings=[AuditFinding(type=item["type"], count=int(item["count"]), confidence=float(item["confidence"]))
                      for item in summarize_findings(inbound_findings)],
            policy_id=decision.policy_ids[0] if decision.policy_ids else None, action="block",
            snippet_redacted=audit_snippet[:500], raw_content=original, latency_ms=elapsed, source=source,
        )
        return ChatResponse(
            response=(
                "Image attachment blocked by the security gateway after OCR inspection."
                if image_text
                else "Request blocked by the security gateway."
            ),
            action_taken="block", findings_summary=summarize_findings(inbound_findings),
            request_id=request_id,
            gateway_report={"policy_ids": decision.policy_ids, "audit_id": event.id,
                            "denied_document_count": retrieval["denied_count"],
                            "denied_doc_ids": retrieval["denied_doc_ids"],
                            "image_text_scanned": bool(image_text)},
        )
    if decision.action == "require_approval":
        approval_id = enqueue_approval(request_id, inbound_findings, audit_snippet[:500])
        elapsed = (time.perf_counter() - started) * 1000
        event = log_event(
            user_id=user.user_id, direction="prompt",
            findings=[AuditFinding(type=item["type"], count=int(item["count"]), confidence=float(item["confidence"]))
                      for item in summarize_findings(inbound_findings)],
            policy_id=decision.policy_ids[0] if decision.policy_ids else None, action="require_approval",
            snippet_redacted=audit_snippet[:500], raw_content=original, latency_ms=elapsed, source=source,
        )
        return ChatResponse(
            response="Request is waiting for human approval.", action_taken="require_approval",
            findings_summary=summarize_findings(inbound_findings), request_id=request_id,
            gateway_report={"policy_ids": decision.policy_ids, "approval_id": approval_id,
                            "audit_id": event.id, "image_text_scanned": bool(image_text)},
        )
    safe_prompt = transform_text(original, inbound_findings, "mask")
    if decision.action == "redact":
        safe_prompt = transform_text(original, inbound_findings, "redact")
    if decision.action == "warn":
        safe_prompt = original
    response = await complete(safe_prompt, context)
    response_findings, _ = await asyncio.gather(
        asyncio.to_thread(inspect, response, "response", user),
        asyncio.to_thread(injection_findings, response, "user"),
    )
    if CANARY_TOKEN in response:
        response_findings.append(
            Finding(category="INJECTION", type="CANARY_LEAK", start=response.index(CANARY_TOKEN),
                    end=response.index(CANARY_TOKEN) + len(CANARY_TOKEN), confidence=1.0, detector="canary")
        )
    outbound = policies.decide(response_findings, "response")
    if outbound.action == "block" or any(item.type == "CANARY_LEAK" for item in response_findings):
        response = "Response blocked because it contained restricted information."
        final_action = "block"
    elif outbound.action == "redact":
        response = transform_text(response, outbound.matched_findings, "redact")
        final_action = "redact"
    else:
        final_action = decision.action
    all_findings = inbound_findings + response_findings
    elapsed = (time.perf_counter() - started) * 1000
    counts = Counter(item.type for item in all_findings)
    event = log_event(
        user_id=user.user_id, direction="prompt",
        findings=[AuditFinding(type=kind, count=count,
                               confidence=max(item.confidence for item in all_findings if item.type == kind))
                  for kind, count in sorted(counts.items())],
        policy_id=(decision.policy_ids or outbound.policy_ids or [None])[0],
        action=final_action, snippet_redacted=audit_snippet[:500],
        raw_content=original, latency_ms=elapsed, source=source,
    )
    return ChatResponse(
        response=response, action_taken=final_action,
        findings_summary=summarize_findings(all_findings), request_id=request_id,
        gateway_report={
            "policy_ids": list(dict.fromkeys(decision.policy_ids + outbound.policy_ids)),
            "audit_id": event.id, "masked_before_model": safe_prompt != original,
            "model_mode": os.getenv("LLM_MODE", "ollama"),
            "denied_document_count": retrieval["denied_count"],
            "denied_doc_ids": retrieval["denied_doc_ids"],
            "image_text_scanned": bool(image_text),
            "sanitized_prompt": safe_prompt,
        },
    )
