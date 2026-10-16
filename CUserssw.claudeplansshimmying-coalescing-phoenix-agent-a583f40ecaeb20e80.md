# Implementation Plan: AI Security Gateway Bug Fixes & Inconsistencies

This plan outlines the steps to resolve several bugs and inconsistencies across the Gateway, Detectors, and RAG components of the AI Security Gateway.

## 1. Gateway & Tracing

### `gateway/pipeline.py`
- **Issue**: `_trace_decision` defaults `require_approval` to `"warn"`.
  - **Fix**: Update `_trace_decision` to include `"require_approval"` in the set of allowed actions.
- **Issue**: `process_chat` may report `"allow"` in `outbound_changes` even if a `CANARY_LEAK` blocked the response.
  - **Fix**: In `process_chat`, ensure that if `final_action` is `"block"`, the `outbound_changes["action"]` is also set to `"block"`. Specifically, review the logic around line 222-245 where `outbound_changes` is constructed.

### `gateway/approvals.py`
- **Issue**: `list_approvals` returns mutable dict values from `_QUEUE` without copying.
  - **Fix**: Update `list_approvals` to return a list of copies of the dictionaries in `_QUEUE`. Use `[item.copy() for item in reversed(list(_QUEUE.values()))]`.

## 2. PII & Injection Detectors

### `detectors/india_pii.py`
- **Issue**: Email regex is too permissive.
  - **Fix**: Tighten the `EMAIL` regex in `PATTERNS`. Current: `r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"`
  - **Proposed**: Use a more robust regex that validates the local part and domain more strictly, e.g., `r"(?<![\w.+-])[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"` (or similar depending on specific requirements).
- **Issue**: Credit card regex may cause false positives.
  - **Fix**: The `CARD` regex `r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"` matches any long sequence of digits.
  - **Proposed**: Refine the regex to be less greedy or add more specific formatting requirements. Since it already uses `valid_luhn`, the regex's primary job is to identify candidates. We can tighten it to ensure it doesn't match generic long numbers (like AADHAAR) by checking for typical card spacing or reducing the range if appropriate.

### `detectors/inspect.py`
- **Issue**: `_SOURCE_CODE` regex is too broad.
  - **Fix**: Current regex: `r"(?m)^\s*(?:def |class |import |from \S+ import |const \w+\s*=|SELECT .+ FROM )"`.
  - **Proposed**: Refine the regex to avoid matching 'def ' inside strings or non-code blocks. While `(?m)^` handles start of line, we can make the patterns more specific (e.g., `def \w+\(`).
- **Issue**: `inspect` accepts `UserContext` but doesn't use it.
  - **Fix**: Add a TODO comment in `inspect` to implement role-based PII detection using `ctx`.

### `injection/rules.py`
- **Issue**: Confidence is lowered to 0.7 for `required_approval` patterns.
  - **Fix**: In the `score` function, remove or increase the confidence penalty for `required_approval` patterns. Currently, it's `0.7 if required_approval and kind in {...} else confidence`.
  - **Proposed**: Either remove this conditional lowering or change 0.7 to a higher value (e.g., 0.9).

## 3. RAG Implementation

### `rag/retriever.py`
- **Issue**: `_retrieve_chroma` silently skips documents that fail `scan_document`.
  - **Fix**: In `_retrieve_chroma`, when `scan_document(text)` returns findings (indicating a security failure), add the `doc_id` to the `denied` list.
  - **Proposed Logic**:
    ```python
    if scan_document(text):
        denied.append(doc_id)
        continue
    ```

## Verification Plan

### 1. Gateway Tests
- Verify `list_approvals` returns copies by modifying a returned item and checking if the internal `_QUEUE` changed.
- Test `process_chat` with a canary token in the LLM response and verify `outbound_changes["action"] == "block"`.

### 2. Detector Tests
- Create a test suite with:
  - Invalid emails that were previously matched.
  - Long numeric strings that aren't credit cards.
  - Text containing "def " at the start of a line that isn't source code.
  - Injection prompts that trigger `required_approval` and verify confidence scores.

### 3. RAG Tests
- Mock `scan_document` to fail for a specific document.
- Verify that document's ID appears in `denied_doc_ids` and is counted in `denied_count`.
