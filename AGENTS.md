# Gemini Guardrail Platform — Engineering & Architecture Rules

These rules apply to all development, testing, and deployments within `gemini_guardrail_demo`.

## 1. Model Tiering & Latency Clamping Invariant
- **Guardrail Judges (Ingress / Egress / Playground)**:
  - Target: `gemini-3.5-flash-lite`
  - Generation Config: Temperature MUST be `0.0`, MIME type MUST be `application/json`.
  - Thinking Budget: MUST explicitly set `"thinkingConfig": {"thinkingBudget": 0}` to clamp reasoning latency to sub-second (<0.9s).
- **Optimizer & Primary Core**:
  - Primary Core: `gemini-3.7-flash` (or `gemini-3.5-flash-lite` for ultra-low-latency core tasks)
  - DSPy Prompt Optimizer (Pass 2): `gemini-3.7-flash` with thinking budget up to `2048` for deep synthesis.

## 2. Cloud Run IAM Authentication Architecture
- Cloud Run services must resolve Vertex AI access tokens dynamically via:
  `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
- Service Account: `<project-number>-compute@developer.gserviceaccount.com` with `roles/aiplatform.admin`.
- Developer OAuth tokens (`ya29...`) provided by the user must ONLY be passed to deployment environment variables (`CLOUDSDK_AUTH_ACCESS_TOKEN`) and never baked into the container.

## 3. Client State & Session Invariants
- **Reassignable State**: Variables that reset between turns (e.g. `conversationHistory`, `customAppSystemPrompt`) MUST be declared with `let`.
- **Clear Chat Action**: Clearing chat history must reset dialogue memory and telemetry meters without wiping active server guardrail rules (`GLOBAL_GUARDRAIL_PROMPT`).

## 4. Pre-Deployment Validation Gate
Before initiating any `gcloud run deploy` or uploading archives:
1. Validate Python: `python3 -m py_compile app.py`
2. Validate JavaScript: Extract `<script>` from `index.html` and verify syntax via `node -c`.
3. Never deploy if either validation fails.
