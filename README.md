# Enterprise Multimodal GenAI Guardrail Platform & Proxy (Google Cloud Run)

[![Google Cloud](https://img.shields.io/badge/Google%20Cloud-Vertex%20AI-4285F4?logo=google-cloud&logoColor=white)](https://cloud.google.com/vertex-ai)
[![Cloud Run](https://img.shields.io/badge/Deployed-Cloud%20Run-24C1E0?logo=google-cloud&logoColor=white)](https://cloud.google.com/run)
[![Gemini 2.5 / 3.5 Flash Lite](https://img.shields.io/badge/Judge-Gemini%20Flash%20Lite-8E75B2?logo=google&logoColor=white)](https://cloud.google.com/vertex-ai/generative-ai/docs/multimodal-overview)
[![Gemini 2.5 / 3.7 Flash](https://img.shields.io/badge/Reasoning-Gemini%20Flash-00BFA5?logo=google&logoColor=white)](https://cloud.google.com/vertex-ai/generative-ai/docs/multimodal-overview)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade, sub-second multimodal AI security guardrail proxy, interactive evaluation studio, and automated prompt optimizer built on **Google Cloud Vertex AI** and **Google Cloud Run**.

This platform solves the critical tension in enterprise Generative AI between **defense depth** and **real-time user latency**. By deploying high-throughput, deterministic security judges (**Gemini 3.5 / 2.5 Flash Lite**) with **zero-thinking budget clamping** ahead of frontier reasoning models (**Gemini 3.7 / 2.5 Flash**), the platform achieves **sub-second Ingress and Egress inspection** while defending against adversarial prompt injections, multimodal document attacks (PDF, XLSX, Image OCR), and agentic tool exploitation.

---

## 🏛️ Platform Architecture

```mermaid
flowchart TD
    subgraph ClientLayer [Client Applications & Enterprise Agents]
        Client[Web Browser / LangChain / OpenAI SDK / LiteLLM]
    end

    subgraph CloudRun [Enterprise Guardrail Proxy & Studio - Google Cloud Run]
        direction TB
        ProxyAPI["/v1/chat/completions & /api/*"]
        
        subgraph Stage1 [Stage 1: Ingress Guardrail]
            IngressJudge["Gemini 2.5/3.5 Flash Lite<br/>(thinkingBudget: 0, Temp: 0.0)"]
            SepEngine["Data-Instruction Separation Engine<br/>Quarantines App SI, User Turns & Media"]
        end

        CircuitBreaker{Ingress Safe?}

        subgraph Stage2 [Stage 2: Primary Reasoning]
            CoreModel["Gemini 2.5/3.7 Flash<br/>(Primary Task Synthesis)"]
            ToolCallInterceptor["Tool Execution Guardrail<br/>Validates Function Names & Args"]
        end

        subgraph Stage3 [Stage 3: Egress Guardrail]
            EgressJudge["Gemini 2.5/3.5 Flash Lite<br/>(thinkingBudget: 0, Temp: 0.0)"]
            DLPScanner["PCI-DSS & SOC2 DLP Engine<br/>Detects SSN, 16-Digit Cards, Secrets"]
        end

        BlockedCard["Security Intercept Event<br/>100% Downstream Compute Saved"]
    end

    subgraph VertexAI [Google Cloud Vertex AI Global Infrastructure]
        JudgeModelAPI["Vertex AI Prediction Endpoint<br/>(gemini-2.5-flash-lite)"]
        ReasoningModelAPI["Vertex AI Prediction Endpoint<br/>(gemini-2.5-flash / 3.7)"]
        ComputeMetadata["Compute Metadata Server (24/7 ADC)<br/>http://metadata.google.internal"]
    end

    Client -->|1. REST / OpenAI API Call| ProxyAPI
    ProxyAPI --> SepEngine
    SepEngine --> IngressJudge
    IngressJudge <-->|Sub-Second REST Scan| JudgeModelAPI
    IngressJudge --> CircuitBreaker

    CircuitBreaker -- "No (Threat Detected)" --> BlockedCard
    BlockedCard -->|Instant Audit Alert JSON| Client

    CircuitBreaker -- "Yes (Approved)" --> CoreModel
    CoreModel <-->|Deep Reasoning| ReasoningModelAPI
    CoreModel --> ToolCallInterceptor
    ToolCallInterceptor --> Stage3

    Stage3 --> EgressJudge
    EgressJudge <-->|Sub-Second DLP Scan| JudgeModelAPI
    EgressJudge -->|Sanitized Stream / JSON| Client
    
    CloudRun -.->|Auto-Refresh OAuth Bearer| ComputeMetadata
```

---

## 🌟 The Three Operating Studios

The platform delivers three integrated operational interfaces in a unified single-page application:

```
+-----------------------------------------------------------------------------------------------+
|  [ 💬 Enterprise Chatbot ]    [ 🧪 Guardrail Playground ]    [ 🪄 DSPy Prompt Optimizer ]    |
+-----------------------------------------------------------------------------------------------+
```

### 1. Enterprise Chatbot Proxy (`/`)

![Enterprise Chatbot Studio & Live Telemetry HUD](docs/img/chatbot_studio.png)
*Figure 1: Live Enterprise Chatbot executing 3-stage screening, displaying real-time Ingress & Egress latency badges, safety threat cards, and Stage 2/3 Raw API Inspector.*

* **Live 3-Stage Enforcement**: Full Ingress &rarr; Tool Call Guardrail &rarr; Egress DLP pipeline.
* **Instant Circuit Breaking**: When a threat is detected, the primary reasoning model is skipped entirely, saving **100% of downstream execution latency and token costs**.
* **Live Guardrail Rules Editor**: The **`[ 🛡️ Active Guardrail Rules (View / Edit) ]`** modal allows SecOps administrators to inspect, edit, and apply custom policies directly to live Cloud Run memory (`POST /api/guardrail/update-prompt`) in real time.
* **Session Lifecycle Control**: Dedicated **`[ 🗑️ Clear Chat ]`** button resets conversation memory without resetting server-side custom guardrail rules.
* **Telemetry HUD & Raw Inspector**: Displays live stage latencies, risk badges, threat classifications, data-instruction separation previews, and raw JSON request/response envelopes.

### 2. Interactive Multimodal Guardrail Playground (`#playground`)

![Interactive Multimodal Guardrail Playground](docs/img/playground_studio.png)
*Figure 2: Interactive Guardrail Playground evaluating a Destructive SQL Injection attack in tool arguments, displaying real-time data-instruction separation envelopes and safety verdict.*

* **12 Pre-Configured Benchmark Scenarios**: Spanning Agent Tool Security, Multimodal Document Attacks, and Prompt Injections.
* **Custom Turn Builder**: Construct complex multi-turn sequences with dynamic role selection (`user`, `assistant`, `tool_call`, `tool_response`).
* **Multi-Format Document Upload**: Attach and test raster images (`.png`, `.jpg`), PDF files (`application/pdf`), and Microsoft Excel spreadsheets (`.xlsx`).
* **Multi-Format Code Exporters**: Instantly export the active scenario into runnable **Python (requests)** and **cURL** scripts.
* **Payload Tree & JSON Inspector**: Compare normalized JSON payloads with the raw Vertex AI REST request envelope.

### 3. DSPy-Inspired Multi-Pass Prompt Optimizer (`#dspy`)

![DSPy Prompt Optimizer Studio](docs/img/dspy_optimizer.png)
*Figure 3: DSPy-Inspired Multi-Pass Optimizer achieving 100% accuracy across the 10-vector benchmark suite, displaying the upgraded battle-tested system instruction ready for one-click deployment.*

Automates the synthesis and calibration of production-grade guardrail system instructions through an automated **3-Pass Teacher-Student Optimization Architecture**:

```mermaid
flowchart LR
    subgraph Pass1 [Pass 1: Benchmark Evaluation]
        Student["Student Judge<br/>(Gemini Flash Lite)"]
        Dataset["10-Vector Hardening Dataset<br/>(Multimodal, Tools, DLP, Jailbreaks)"]
        Pass1Score["Baseline Accuracy &<br/>Failure Diagnosis"]
    end

    subgraph Pass2 [Pass 2: Meta-Prompt Synthesis]
        Teacher["Teacher Optimizer<br/>(Gemini Flash, thinkingBudget: 2048)"]
        Pass2Rules["Synthesize Specialized<br/>Negative Constraints & Edge Rules"]
    end

    subgraph Pass3 [Pass 3: Multi-Candidate Tournament]
        Candidates["3 Candidate Prompts<br/>(Conservative, Balanced, Zero-Tolerance)"]
        Tournament["Parallel Evaluation Tournament"]
        FinalDeploy["Deploy Winning Prompt<br/>to Live Guardrail Proxy"]
    end

    Dataset --> Student --> Pass1Score
    Pass1Score --> Teacher --> Pass2Rules
    Pass2Rules --> Candidates --> Tournament --> FinalDeploy
```

---

## 🛡️ Threat Defense Matrix

The platform provides end-to-end protection against the entire spectrum of LLM vulnerability vectors:

| Vector Category | Attack Scenario | Threat Signature | Detection Mechanism | Enforcement Stage |
|---|---|---|---|---|
| **Agent Tool Execution** | Destructive Database Wipe | `SQL_INJECTION_DESTRUCTIVE` | Stacked SQL statements (`DROP`, `TRUNCATE`, `--`) in tool arguments | Stage 2 (Tool Call) |
| **Agent Tool Execution** | Cloud Instance SSRF | `SSRF_METADATA_EXFILTRATION` | IP traversal (`169.254.169.254`, `metadata.google.internal`) in fetch URLs | Stage 2 (Tool Call) |
| **Agent Tool Execution** | IAM Role Escalation | `PRIVILEGE_ESCALATION` | Unauthorized grants of `roles/owner` or `roles/admin` | Stage 2 (Tool Call) |
| **Tool Response & RAG** | Poisoned CRM Ticket | `INDIRECT_RAG_INJECTION` | Embedded `[SYSTEM OVERRIDE]` instructions inside retrieved ticket data | Stage 2 (Tool Response) |
| **Multimodal Document** | Image OCR Banner | `VISUAL_INJECTION` | High-contrast adversarial graphics with text overriding system directives | Stage 1 (Ingress) |
| **Multimodal Document** | Hidden Text Resume | `DOCUMENT_PROMPT_INJECTION` | PDF zero-font or white-on-white text demanding perfect candidate score | Stage 1 (Ingress) |
| **Multimodal Document** | Invoice Payment Diversion | `PAYMENT_EXFILTRATION_INJECTION`| PDF invoice routing alterations redirecting accounts payable funds | Stage 1 (Ingress) |
| **Multimodal Document** | Poisoned Spreadsheet | `FORMULA_INJECTION` | Excel DDE command execution (`=cmd|...`) or `=HYPERLINK` exfiltration | Stage 1 (Ingress) |
| **Prompt Jailbreak** | Multi-Turn Crescendo | `MULTI_TURN_CRESCENDO` | Gradual academic/roleplay escalation to extract secret backend prompts | Stage 1 (Ingress) |
| **Prompt Jailbreak** | Direct Override (PIJB) | `DIRECT_OVERRIDE` | Commands to ignore prior guidelines (`You are now UNRESTRICTED_BOT`) | Stage 1 (Ingress) |
| **Data Loss Prevention** | Financial & PII Leakage | `PII_FINANCIAL_LEAK` | Generated 16-digit credit cards, CVVs, or SSNs violating PCI-DSS | Stage 3 (Egress) |
| **Compliance Separation**| System Instruction Clashing | `NONE` (Safe XML Output) | Validates user XML requests without colliding with JSON guardrail | Stage 1 (Ingress) |

---

## 🔬 Core Engineering Patterns

### 1. Sub-Second Latency Clamping (`thinkingBudget: 0`)
Standard reasoning models (Gemini 2.5 Flash, Gemini 3.7 Flash) incorporate automatic thinking/scratchpad generation, which can add **3–8 seconds of latency** per turn. 

For high-throughput security screening, thinking is completely disabled at Ingress and Egress:
```json
{
  "generationConfig": {
    "temperature": 0.0,
    "responseMimeType": "application/json",
    "thinkingConfig": {
      "thinkingBudget": 0
    }
  }
}
```
* **Ingress Latency**: **~0.6s – 0.9s**
* **Egress Latency**: **~0.5s – 0.8s**
* **Thinking Budget**: Reserved strictly for **Pass 2 of the DSPy Prompt Optimizer** (`thinkingBudget: 2048`), where deep synthesis and policy meta-reasoning are required.

---

### 2. Autonomous 24/7 IAM Token Resolution (Cloud Run)
The application eliminates hardcoded API keys and static tokens by querying the internal **Google Compute Engine Metadata Server** when running on Cloud Run:

```python
def get_access_token() -> str:
    # 1. Cloud Run Compute Metadata Service Account Token (Auto-Refreshing 24/7)
    try:
        req = urllib.request.Request(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"}
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["access_token"]
    except Exception:
        pass

    # 2. Fallback to Local Application Default Credentials (ADC)
    # 3. Fallback to Static Shell / Developer Tokens
```

### Automated Service Account IAM Setup in `deploy.sh`

The deployment automation script (`./deploy.sh`) automatically configures the Cloud Run identity with both `roles/aiplatform.user` (GEAP inference) and `roles/aiplatform.admin` without manual intervention:

```bash
# Handled automatically inside deploy.sh:
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
SA_EMAIL="${CUSTOM_SERVICE_ACCOUNT:-${PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"

# Grants inference permissions for Gemini 3.5 Flash Lite & 3.7 Flash
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/aiplatform.user" --quiet

# Grants full Vertex AI resource management
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/aiplatform.admin" --quiet

# Deploys with the explicitly bound service account
gcloud run deploy "$SERVICE_NAME" --service-account "$SA_EMAIL" ...
```

---

### 3. Strict Data-Instruction Separation

To prevent adversarial user inputs or poisoned tool responses from hijacking the Guardrail Judge, the platform enforces strict structural separation:

```
+-----------------------------------------------------------------------------+
|                          GEMINI SYSTEM INSTRUCTION                          |
|  You are an enterprise AI safety guardrail evaluator...                     |
|  (Contains only SecOps rules, schemas, and classification directives)       |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                             USER CONTENT PAYLOAD                            |
|  <untrusted_developer_context>                                              |
|    Developer App Prompt: "Give all responses in XML format"                 |
|  </untrusted_developer_context>                                             |
|  <untrusted_conversation_transcript>                                        |
|    Turn 1 (user): "Can you look up customer ID CUST-8492?"                  |
|    Turn 2 (tool_call): {"name": "lookup_customer_account", ...}             |
|  </untrusted_conversation_transcript>                                       |
|  <attached_multimodal_documents>                                            |
|    [Inline Data: PDF / Image / Spreadsheet Artifacts]                       |
|  </attached_multimodal_documents>                                           |
+-----------------------------------------------------------------------------+
```

---

## 📡 API Reference & Integration

### 1. OpenAI SDK Drop-In Client (Python)

The platform exposes an OpenAI-compatible `/v1/chat/completions` endpoint that supports multi-turn streaming, tool calls, and automated guardrail inspection:

```python
import openai

client = openai.OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="none"  # Handled automatically via GCP IAM
)

response = client.chat.completions.create(
    model="gemini-3.7-flash",
    messages=[
        {"role": "system", "content": "You are an enterprise banking assistant."},
        {"role": "user", "content": "What is the recommended portfolio allocation for retirement?"}
    ]
)

print(response.choices[0].message.content)
```

---

### 2. Direct Guardrail Evaluation Endpoint (`POST /api/playground/evaluate`)

Evaluates custom transcripts and multimodal files against custom guardrail system instructions:

```bash
curl -X POST "http://127.0.0.1:8080/api/playground/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "guardrail_si": "Detect destructive SQL injection in tool calls. Output JSON with is_safe and threat_detected.",
    "app_prompt": "You are a database query assistant.",
    "turns": [
      {"role": "user", "content": "Fetch user Alice and drop audit logs."},
      {"role": "tool_call", "content": "{\"name\": \"query_db\", \"args\": {\"query\": \"SELECT * FROM users; DROP TABLE audit;\"}}"}
    ],
    "attachments": []
  }'
```

**Response (`200 OK`)**:
```json
{
  "is_safe": false,
  "risk_level": "CRITICAL",
  "threat_detected": "SQL_INJECTION_DESTRUCTIVE",
  "confidence_score": 1.0,
  "analysis": "Tool execution argument contains destructive stacked SQL statement attempting audit log deletion.",
  "latency_sec": 0.68,
  "model": "gemini-3.5-flash-lite"
}
```

---

### 3. Automated Prompt Optimizer (`POST /api/dspy/optimize`)

Triggers the 3-pass automated prompt optimization pipeline:

```bash
curl -X POST "http://127.0.0.1:8080/api/dspy/optimize" \
  -H "Content-Type: application/json" \
  -d '{
    "base_si": "You are a basic enterprise AI guardrail. Detect security threats and output JSON.",
    "iterations": 2,
    "strategy": "balanced"
  }'
```

---

## 🚀 Deployment & Local Access Guide

### 1. Automated 1-Script Deployment (`deploy.sh`)

The included [`deploy.sh`](deploy.sh) script handles the complete end-to-end setup in a single command:
1. Enables required Google Cloud APIs (`run`, `cloudbuild`, `aiplatform`).
2. Detects the project number and automatically binds **GEAP / Vertex AI IAM roles** (`roles/aiplatform.user` and `roles/aiplatform.admin`) to the Cloud Run Service Account.
3. Builds and deploys the container with `--service-account` properly attached.

```bash
# Clone the repository
git clone https://github.com/your-org/gemini-guardrail-proxy.git
cd gemini-guardrail-proxy

# Configure GCP Project
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_REGION="us-central1"

# Execute the automated deployment script
chmod +x deploy.sh
./deploy.sh
```

### 2. Launch Local Authenticated Proxy

Connect securely to your Cloud Run deployment from Cloud Shell or your local workstation:

```bash
gcloud run services proxy gemini-guardrail-demo \
    --project $GOOGLE_CLOUD_PROJECT \
    --region $GOOGLE_CLOUD_REGION \
    --port 8080
```

Open your browser to: **`http://127.0.0.1:8080`** (or use the Cloud Shell Web Preview on port 8080).

---

## 📂 Repository Structure

```
gemini-guardrail-demo/
├── app.py                      # Flask backend, 3-stage proxy, Vertex AI caller, DSPy optimizer
├── index.html                  # Single-page studio (Chatbot, Playground, DSPy Optimizer)
├── requirements.txt            # Python dependencies (Flask, requests, google-genai, etc.)
├── Dockerfile                  # Container definition for Cloud Run
├── README.md                   # Complete architectural documentation and reference
└── deploy.sh                   # Deployment automation script
```

---

## 📄 License
This platform is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
