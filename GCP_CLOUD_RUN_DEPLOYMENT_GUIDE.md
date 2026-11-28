# Google Cloud Platform (GCP) Cloud Run — Step-by-Step Deployment Guide

This guide walks through **every step**—both in the **Google Cloud Console (UI)** and via the **`gcloud` CLI**—to deploy the **Azure FinSecOps & Governance Platform** to **Google Cloud Run** with **Google Cloud Vertex AI** (`VERTEX_AI_API_KEY`).

---

## Architecture Overview on GCP

```text
Browser (User)
   │  HTTPS
   ▼
Google Cloud Run (Container Port 8000)
   ├── Flask App (app.py) + 32 Assessment Modules (14 Security + 18 Cost)
   ├── Vertex AI Agent (app/agent/provider.py) ──► aiplatform.googleapis.com
   ├── Secret Manager ──► injects VERTEX_AI_API_KEY at runtime
   └── Outbound HTTPS (TCP 443) ──► login.microsoftonline.com
                                ──► management.azure.com
                                ──► prices.azure.com
```

---

## Part 1: Code & Container Readiness Check (What Is Already Configured vs. Optional Changes)

Before deploying to Cloud Run, verify your repository files:

1. **Port & Host Binding ([app.py](file:///c:/Users/mnave/OneDrive/Desktop/Azure/app.py#L890-L898))**:
   - Cloud Run automatically injects the `PORT` environment variable (default `8080`, or `8000` if configured).
   - `app.py` already reads `PORT` first, then `APP_PORT`, and binds to `0.0.0.0`:
     ```python
     host = os.getenv("APP_HOST", "0.0.0.0")
     port = int(os.getenv("PORT", os.getenv("APP_PORT", "8000")))
     app.run(host=host, port=port, debug=False, threaded=True)
     ```
   - **No code change required.**

2. **Health Check Endpoint ([app.py](file:///c:/Users/mnave/OneDrive/Desktop/Azure/app.py#L58-L60))**:
   - `/health` and `/api/health` are already implemented and return HTTP `200`.

3. **Dockerfile ([Dockerfile](file:///c:/Users/mnave/OneDrive/Desktop/Azure/Dockerfile))**:
   - Uses `python:3.12-slim`, installs `requirements.txt`, copies `app/`, `templates/`, `static/`, `app.py`, exposes `8000`, and runs `CMD ["python", "app.py"]`.
   - **Important:** Do **not** `COPY .env .` into the Docker image—secrets should be injected via **Secret Manager** in Cloud Run.
   - *(Optional production hardening)*: If you want Gunicorn instead of Flask's built-in threaded server, add `gunicorn>=22.0.0` to `requirements.txt` and change the last line of `Dockerfile` to:
     ```dockerfile
     CMD ["sh", "-c", "gunicorn -w 1 --threads 8 -b 0.0.0.0:${PORT:-8000} --timeout 300 app:app"]
     ```
     *(Keep `-w 1` because `CONNECTIONS`, `JOBS`, and `REPORTS` are stored in memory.)*

4. **Create a `.dockerignore` file (Recommended)** in the project root so local caches, tests, and `.env` are not uploaded to Cloud Build:
   ```text
   .git
   .venv
   venv
   __pycache__
   .pytest_cache
   .ruff_cache
   .env
   tests/
   docs/
   example_assessment/
   *.md
   ```

---

## Part 2: Google Cloud Project & APIs Setup

### Step 1: Select or Create a GCP Project & Enable Billing
1. Open the **[Google Cloud Console](https://console.cloud.google.com/)**.
2. In the top navigation bar, click the **Project selector dropdown** (next to "Google Cloud").
3. Click **New Project** (top-right of the modal) or select an existing project:
   - **Project name:** e.g., `azure-finsecops-prod`
   - Click **Create**.
4. Ensure Billing is linked:
   - Open the **Navigation Menu (☰)** → **Billing** → link a billing account if prompted.

### Step 2: Enable Required Google Cloud APIs
**Via Cloud Console UI:**
1. Open **Navigation Menu (☰)** → **APIs & Services** → **Library**.
2. Search for and click **Enable** on each of the following 5 APIs:
   - **Cloud Run Admin API** (`run.googleapis.com`)
   - **Artifact Registry API** (`artifactregistry.googleapis.com`)
   - **Cloud Build API** (`cloudbuild.googleapis.com`)
   - **Secret Manager API** (`secretmanager.googleapis.com`)
   - **Vertex AI API** (`aiplatform.googleapis.com`)

**Or via `gcloud` CLI:**
```bash
gcloud auth login
gcloud config set project YOUR_GCP_PROJECT_ID

gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  aiplatform.googleapis.com
```

---

## Part 3: Create & Secure Your Vertex AI API Key

### Step 3: Create a Vertex AI API Key
1. In the Google Cloud Console, go to **Navigation Menu (☰)** → **APIs & Services** → **Credentials**.
2. Click **+ CREATE CREDENTIALS** at the top → select **API key**.
3. Copy the generated API key immediately.
4. Click **Edit API key** (or the key name) to restrict it:
   - Under **API restrictions**, select **Restrict key**.
   - In the dropdown, check **Vertex AI API** → click **OK** → **Save**.

### Step 4: Store the Key in Secret Manager
**Via Cloud Console UI:**
1. Open **Navigation Menu (☰)** → **Security** → **Secret Manager**.
2. Click **+ CREATE SECRET**.
3. Fill in:
   - **Name:** `vertex-ai-api-key`
   - **Secret value:** Paste the Vertex AI API key you copied in Step 3.
4. Click **Create secret**.

**Grant Cloud Run access to the secret:**
1. While inside the `vertex-ai-api-key` secret page, click the **PERMISSIONS** tab.
2. Click **+ GRANT ACCESS**.
3. In **New principals**, enter your Cloud Run runtime service account:
   - Default Compute Engine service account format: `YOUR_PROJECT_NUMBER-compute@developer.gserviceaccount.com`
   - *(You can find your Project Number under **Navigation Menu (☰) → Cloud Overview → Dashboard**.)*
4. Under **Select a role**, search for and select **Secret Manager Secret Accessor**.
5. Click **Save**.

**Or via `gcloud` CLI:**
```bash
echo -n "YOUR_VERTEX_AI_API_KEY" | gcloud secrets create vertex-ai-api-key --data-file=-

PROJECT_NUMBER=$(gcloud projects describe YOUR_GCP_PROJECT_ID --format="value(projectNumber)")
gcloud secrets add-iam-policy-binding vertex-ai-api-key \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

---

## Part 4: Build & Push the Container Image to Artifact Registry

### Step 5: Create an Artifact Registry Repository
**Via Cloud Console UI:**
1. Open **Navigation Menu (☰)** → **CI/CD** → **Artifact Registry** → **Repositories**.
2. Click **+ CREATE REPOSITORY**.
3. Configure:
   - **Name:** `finsecops-repo`
   - **Format:** `Docker`
   - **Mode:** `Standard`
   - **Location type:** `Region` → select e.g. `us-central1` (or your preferred region).
4. Click **Create**.

**Or via `gcloud` CLI:**
```bash
gcloud artifacts repositories create finsecops-repo \
  --repository-format=docker \
  --location=us-central1 \
  --description="Azure FinSecOps Platform container images"
```

### Step 6: Upload Your Project & Build the Image (No GitHub or Azure DevOps Required)

You do **not** need GitHub or Azure DevOps (ADO) to deploy to Cloud Run. Choose **Method A** (100% in the browser, nothing to install on your laptop) or **Method B** (from your local terminal):

#### Method A: Manual Zip Upload via Google Cloud Shell (Browser-Only, No Local Tools Needed)
1. **Create a `.zip` of your project on Windows:**
   - Open `c:\Users\mnave\OneDrive\Desktop\Azure` in File Explorer.
   - Select **only** what is needed (`app/`, `static/`, `templates/`, `app.py`, `Dockerfile`, `requirements.txt`, and `.dockerignore` if created).
   - **Do NOT include** `.env`, `.venv`, `__pycache__`, `.git`, or `.pytest_cache`.
   - Right-click → **Compress to ZIP file** (e.g., `azure-finsecops.zip`).
2. **Open Cloud Shell in Google Cloud Console:**
   - In the top-right bar of the Google Cloud Console, click the **Activate Cloud Shell (`>_`)** icon.
   - Wait a few seconds for the terminal pane to open at the bottom of your browser.
3. **Upload the ZIP file:**
   - In the Cloud Shell toolbar (top-right of the terminal pane), click the **three dots (`⋮`)** → **Upload** → **Choose Files** → select `azure-finsecops.zip` → click **Upload**.
4. **Unzip & Build the Docker image in Cloud Shell:**
   ```bash
   mkdir -p ~/azure-finsecops && unzip -o azure-finsecops.zip -d ~/azure-finsecops
   cd ~/azure-finsecops
   gcloud config set project YOUR_GCP_PROJECT_ID

   gcloud builds submit \
     --tag us-central1-docker.pkg.dev/YOUR_GCP_PROJECT_ID/finsecops-repo/azure-finsecops:latest
   ```
   Cloud Build automatically builds the image from your uploaded `Dockerfile` and pushes it to Artifact Registry.

#### Method B: Direct Upload from Local Terminal via `gcloud` CLI (No GitHub/ADO, No Docker Needed)
If you have the [Google Cloud SDK (`gcloud`)](https://cloud.google.com/sdk/docs/install) installed locally, open PowerShell in `c:\Users\mnave\OneDrive\Desktop\Azure` and run:

```bash
gcloud builds submit \
  --tag us-central1-docker.pkg.dev/YOUR_GCP_PROJECT_ID/finsecops-repo/azure-finsecops:latest
```
`gcloud` automatically zips your local folder (respecting `.dockerignore`), uploads it to Cloud Build, builds the image, and pushes it to Artifact Registry.

#### Method C: Local Docker Desktop (Optional)
```bash
gcloud auth configure-docker us-central1-docker.pkg.dev
docker build -t us-central1-docker.pkg.dev/YOUR_GCP_PROJECT_ID/finsecops-repo/azure-finsecops:latest .
docker push us-central1-docker.pkg.dev/YOUR_GCP_PROJECT_ID/finsecops-repo/azure-finsecops:latest
```

---

## Part 5: Deploy to Google Cloud Run

### Step 7: Create & Configure the Cloud Run Service

**Via Cloud Console UI (Click-by-Click):**
1. Open **Navigation Menu (☰)** → **Serverless** → **Cloud Run**.
2. Click **Deploy container** (or **Create Service**).
3. Select **Deploy one revision from an existing container image**:
   - Click **SELECT** next to *Container image URL*.
   - Expand **Artifact Registry** → `us-central1` → `finsecops-repo` → `azure-finsecops` → select the `latest` tag → click **Select**.
4. Configure **Service settings**:
   - **Service name:** `azure-finsecops`
   - **Region:** `us-central1` (match your Artifact Registry region)
   - **Authentication:**
     - Select **Allow public access** (unauthenticated invocations) if users will open the web UI directly in a browser, **OR** select **Require authentication** if behind Identity-Aware Proxy (IAP) / internal load balancer.
5. Expand **Container(s), Volumes, Networking, Security**:
   - **Container tab → General:**
     - **Container port:** `8000`
   - **Container tab → Resources:**
     - **Memory:** `2 GiB` (recommended for PDF/Excel report generation and multi-subscription scans)
     - **CPU:** `2`
     - **Request timeout:** `300` seconds
   - **Container tab → Revision scaling:**
     - **Minimum number of instances:** `0` (or `1` to avoid cold starts)
     - **Maximum number of instances:** **`1`**
       > **Critical:** Because active Azure connections, background assessment jobs, and generated reports are stored in memory (`CONNECTIONS`, `JOBS`, `REPORTS` in `app.py`), setting **Maximum instances = `1`** ensures every API poll and report download hits the same container instance.
   - **Container tab → Variables & Secrets:**
     - Under **Environment variables**, click **+ ADD VARIABLE** for each:
       | Name | Value |
       | :--- | :--- |
       | `APP_ENV` | `production` |
       | `APP_HOST` | `0.0.0.0` |
       | `VERTEX_AI_MODEL` | `gemini-2.5-flash` *(or `gemini-2.5-pro`)* |
       | `VERTEX_AI_LOCATION` | `global` |
       | `MAX_CONCURRENT_SUBSCRIPTIONS` | `5` |
       | `MAX_CONCURRENT_ASSESSMENTS` | `8` |
     - Under **Secrets**, click **+ REFERENCE A SECRET**:
       - **Secret:** `vertex-ai-api-key`
       - **Reference method:** `Exposed as environment variable`
       - **Name:** `VERTEX_AI_API_KEY`
       - **Version:** `latest`
       - Click **Done**.
   - **Container tab → Health checks (Startup probe):**
     - **Probe type:** `HTTP`
     - **Path:** `/health`
     - **Port:** `8000`
6. Click **Create** (at the bottom). Wait 1–2 minutes for the revision to turn green.

**Or via `gcloud` CLI:**
```bash
gcloud run deploy azure-finsecops \
  --image us-central1-docker.pkg.dev/YOUR_GCP_PROJECT_ID/finsecops-repo/azure-finsecops:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --port 8000 \
  --cpu 2 \
  --memory 2Gi \
  --timeout 300 \
  --min-instances 0 \
  --max-instances 1 \
  --set-env-vars "APP_ENV=production,APP_HOST=0.0.0.0,VERTEX_AI_MODEL=gemini-2.5-flash,VERTEX_AI_LOCATION=global,MAX_CONCURRENT_SUBSCRIPTIONS=5,MAX_CONCURRENT_ASSESSMENTS=8" \
  --set-secrets "VERTEX_AI_API_KEY=vertex-ai-api-key:latest"
```

---

## Part 6: Post-Deployment Verification & Troubleshooting

### Step 8: Verify the Live Application
1. On the Cloud Run service details page, copy the **URL** at the top (e.g. `https://azure-finsecops-xxxxx-uc.a.run.app`).
2. Test the health endpoint: `https://YOUR_SERVICE_URL/health` → should return `200 OK`.
3. Open `https://YOUR_SERVICE_URL` in your browser:
   - Enter your Azure **Tenant ID**, **Client ID**, **Client Secret**, and **Subscription ID(s)** and click **Connect Azure**.
   - Click **Run All Assessments** (or **Run Cost** / **Run Security**).
   - Download the **PDF** and **Excel** reports.
   - Open the **FinSecOps AI Advisor** chat and ask a question (e.g., *"Summarize my latest cost findings"*) to confirm **Vertex AI** responds and executes tools.

### Common Issues & Fixes
| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Container fails startup probe on port `8080` | Cloud Run container port mismatch | Set **Container port** to `8000` in Cloud Run (matching `EXPOSE 8000` and `app.py`). |
| `Job not found` or `Connection not found` during polling | Multiple Cloud Run instances running | Set **Maximum number of instances** to `1` in Cloud Run revision scaling. |
| AI chat shows `Vertex AI API Key Required` | Secret not mounted or missing IAM role | Verify `VERTEX_AI_API_KEY` secret reference and `Secret Manager Secret Accessor` role on the runtime service account. |
| `Vertex AI authentication failed (HTTP 403)` | API key restricted or Vertex AI API disabled | Ensure `aiplatform.googleapis.com` is enabled and the API key allows **Vertex AI API**. |
| `504 Gateway Timeout` on large tenants | Scan exceeds default timeout | Increase Cloud Run **Request timeout** to `300`–`600` seconds. |
