# End-to-End Azure Container Apps (ACA) Deployment Guide
## Complete Beginner-Friendly Blueprint: From Local Code to Production Cloud

---

### Table of Contents
1. [Overview & Why Azure Container Apps?](#1-overview--why-azure-container-apps)
2. [Prerequisites Checklist](#2-prerequisites-checklist)
3. [Step 0: Install and Log In to Azure CLI](#step-0-install-and-log-in-to-azure-cli)
4. [Step 1: Set Up Project Deployment Variables](#step-1-set-up-project-deployment-variables)
5. [Step 2: Create Azure Resource Group](#step-2-create-azure-resource-group)
6. [Step 3: Create Azure Container Registry (ACR)](#step-3-create-azure-container-registry-acr)
7. [Step 4: Build and Push Docker Image (No Local Docker Needed)](#step-4-build-and-push-docker-image-no-local-docker-needed)
8. [Step 5: Create Azure Container Apps Environment](#step-5-create-azure-container-apps-environment)
9. [Step 6: Deploy the Live Container App](#step-6-deploy-the-live-container-app)
10. [Step 7: Verify and Access Your Live Web Application](#step-7-verify-and-access-your-live-web-application)
11. [Step 8: How to Update Your Code in the Future (Continuous Deployment)](#step-8-how-to-update-your-code-in-the-future)
12. [Alternative: Deploying Completely via Azure Portal (GUI / Point-and-Click)](#alternative-deploying-via-azure-portal-gui)
13. [Future Enhancement: Attaching a Custom Domain with Free SSL/TLS](#future-enhancement-attaching-a-custom-domain-with-free-ssltls)
14. [Troubleshooting & Pro-Tips](#troubleshooting--pro-tips)

---

## 1. Overview & Why Azure Container Apps?

**Azure Container Apps (ACA)** is Microsoft's modern, fully-managed serverless container platform built on Kubernetes (K8s) and Envoy. 

### Why this is the best choice for this platform:
* **Zero Kubernetes Headache**: You do not have to manage nodes, clusters, or complex YAML manifests.
* **Built-in Free HTTPS / TLS**: Azure immediately provisions a secure `https://<your-app>.<region>.azurecontainerapps.io` public URL without needing to purchase an SSL certificate or domain today.
* **Serverless Cost Efficiency**: It scales automatically based on incoming web requests. If traffic is low, it uses minimal resources (or scales to zero if desired), keeping cloud hosting costs extremely low.
* **Integrated Secrets & Environment Variables**: Securely store your `AI_PROVIDER`, `GROQ_API_KEY`, and Azure client credentials.

---

## 2. Prerequisites Checklist

Before running any commands, confirm you have:

1. **Active Microsoft Azure Subscription**:
   * If you don't have one, create a free account at [https://azure.microsoft.com/free](https://azure.microsoft.com/free) (includes \$200 credits).
2. **Azure CLI (Command Line Interface)**:
   * Installed on your Windows PC (instructions in Step 0).
3. **No Local Docker Required!**
   * Azure can build the container directly in the cloud using **ACR Cloud Build** (`az acr build`). You do not even need Docker Desktop installed locally.

---

## Step 0: Install and Log In to Azure CLI

Open **PowerShell** (or Terminal) on your computer.

### 1. Install Azure CLI (if not already installed)
Run:
```powershell
winget install -e --id Microsoft.AzureCLI
```
*Alternatively, download the MSI installer from [Microsoft Learn: Install Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows).*

### 2. Verify Installation
Close and reopen your PowerShell window, then check:
```powershell
az version
```

### 3. Log In to Azure
Run the login command:
```powershell
az login
```
A browser window will open. Select your Microsoft account associated with your Azure subscription.

### 4. Select Your Subscription
List your available subscriptions:
```powershell
az account list --output table
```
Set the active subscription where you want to deploy:
```powershell
az account set --subscription "<YOUR_SUBSCRIPTION_NAME_OR_ID>"
```

### 5. Install Container Apps Extension
Enable the containerapp CLI extension and register required resource providers:
```powershell
az extension add --name containerapp --upgrade
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights
az provider register --namespace Microsoft.ContainerRegistry
```

---

## Step 1: Set Up Project Deployment Variables

To avoid typing long names multiple times, define PowerShell variables. Copy and paste the following block into your PowerShell window:

```powershell
# Navigate to your project folder
cd c:\Users\mnave\OneDrive\Desktop\Azure

# Deployment Configuration
$RESOURCE_GROUP   = "rg-finsecops-prod"
$LOCATION         = "eastus"                 # You can use centralindia, westeurope, etc.
$ACR_NAME         = "acrfinsecops$((Get-Random -Minimum 1000 -Maximum 9999))" # Must be unique lowercase alphanumeric
$ENVIRONMENT_NAME = "cae-finsecops-env"
$APP_NAME         = "azure-finsecops-app"
$CONTAINER_PORT   = 8000
```

> **Note on ACR Name**: Azure Container Registry names must be globally unique across all Azure users (only lowercase letters and numbers, no dashes). The `$((Get-Random...))` suffix guarantees a unique name.

---

## Step 2: Create Azure Resource Group

A **Resource Group** is a logical container where all resources for this project (registry, container app, logs) will live together.

Run:
```powershell
az group create `
  --name $RESOURCE_GROUP `
  --location $LOCATION
```

**Expected output:**
```json
{
  "id": "/subscriptions/.../resourceGroups/rg-finsecops-prod",
  "location": "eastus",
  "name": "rg-finsecops-prod",
  "properties": {
    "provisioningState": "Succeeded"
  }
}
```

---

## Step 3: Create Azure Container Registry (ACR)

The **Azure Container Registry (ACR)** is your private cloud storage for Docker images.

Run:
```powershell
az acr create `
  --resource-group $RESOURCE_GROUP `
  --name $ACR_NAME `
  --sku Basic `
  --admin-enabled true
```

* `--sku Basic`: Most cost-effective tier (less than \$5/month).
* `--admin-enabled true`: Generates username/passwords so Azure Container Apps can easily pull your container image.

---

## Step 4: Build and Push Docker Image (No Local Docker Needed)

Instead of running Docker on your laptop, run Azure's cloud-native build engine. This reads your `Dockerfile`, installs packages from `requirements.txt`, and stores the finished image inside your private ACR:

```powershell
az acr build `
  --registry $ACR_NAME `
  --image azure-finsecops:v1.0 .
```

*Note the trailing dot (`.`): it represents the current directory.*

Azure CLI will package your project files, upload them to Azure, build the Linux container image, and tag it as `azure-finsecops:v1.0`. When complete, you will see `Build Succeeded`.

---

## Step 5: Create Azure Container Apps Environment

The **Container Apps Environment** acts as the secure network perimeter and hosting environment for your apps.

Run:
```powershell
az containerapp env create `
  --name $ENVIRONMENT_NAME `
  --resource-group $RESOURCE_GROUP `
  --location $LOCATION
```

*This typically takes 40–90 seconds to provision Azure Log Analytics and Envoy ingress routers.*

---

## Step 6: Deploy the Live Container App

Now deploy your container to the web with external ingress (public Internet access) and automated HTTPS.

### 1. Retrieve the ACR Login Server and Password
```powershell
$ACR_SERVER = az acr show --name $ACR_NAME --query loginServer --output tsv
$ACR_PASSWORD = az acr credential show --name $ACR_NAME --query "passwords[0].value" --output tsv
```

### 2. Deploy Container App
Replace `<YOUR_GROQ_API_KEY>` with your actual Groq API key:

```powershell
az containerapp create `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --environment $ENVIRONMENT_NAME `
  --image "$ACR_SERVER/azure-finsecops:v1.0" `
  --target-port $CONTAINER_PORT `
  --ingress external `
  --registry-server $ACR_SERVER `
  --registry-username $ACR_NAME `
  --registry-password $ACR_PASSWORD `
  --cpu 0.5 `
  --memory 1.0Gi `
  --min-replicas 1 `
  --max-replicas 3 `
  --env-vars `
    AI_PROVIDER="groq" `
    GROQ_API_KEY="<YOUR_GROQ_API_KEY>" `
    GROQ_MODEL="llama-3.3-70b-versatile" `
    APP_HOST="0.0.0.0" `
    APP_PORT="8000"
```

### What these parameters do:
* `--target-port 8000`: Matches the Flask port configured in `Dockerfile` and `app.py`.
* `--ingress external`: Assigns a public, internet-reachable HTTPS endpoint.
* `--cpu 0.5 --memory 1.0Gi`: Modest, cost-optimized resources for running the Flask server, AI orchestrator, and report generators.
* `--min-replicas 1`: Keeps at least 1 instance always active so requests respond instantly without cold-start delays.

---

## Step 7: Verify and Access Your Live Web Application

### 1. Retrieve Your Public URL
Run:
```powershell
$APP_URL = az containerapp show `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --query properties.configuration.ingress.fqdn `
  --output tsv

Write-Host "==========================================" -ForegroundColor Green
Write-Host "Your Live FinSecOps Application URL:" -ForegroundColor Yellow
Write-Host "https://$APP_URL" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Green
```

### 2. Open in Browser
Copy the URL (e.g. `https://azure-finsecops-app.delightfulglade-XXXX.eastus.azurecontainerapps.io`) and paste it into Chrome, Edge, or Firefox.

You will see:
* The native unified Azure FinSecOps interface.
* Working AI Chat Assistant powered by the configured LLM.
* Working Security & Cost Assessment tabs.
* Working Scheduled Routines & Email Dispatcher.

---

## Step 8: How to Update Your Code in the Future

Whenever you modify any code, HTML, CSS, or backend logic in the future, updating production takes only **two commands**:

### Step A: Build a new version image in ACR
```powershell
az acr build --registry $ACR_NAME --image azure-finsecops:v1.1 .
```

### Step B: Update the running Container App
```powershell
az containerapp update `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --image "$ACR_SERVER/azure-finsecops:v1.1"
```

Azure Container Apps will automatically perform a **zero-downtime rolling update**: it starts the new container version, verifies health checks, and seamlessly switches all live traffic to the new version before terminating the old one!

---

## Alternative: Deploying via Azure Portal (GUI)

If you prefer clicking in the Azure Web Portal instead of using PowerShell commands:

1. **Sign in** to [portal.azure.com](https://portal.azure.com).
2. Search for **Container Apps** in the top search bar and click **Create**.
3. **Basics Tab**:
   * *Subscription*: Select your subscription.
   * *Resource Group*: Create new -> `rg-finsecops-prod`.
   * *Container App Name*: `azure-finsecops-app`.
   * *Region*: e.g. `East US`.
   * *Container Apps Environment*: Click *Create new*, give it a name (`cae-finsecops`), and click *OK*.
4. **App Settings Tab (Container)**:
   * *Image Source*: Azure Container Registry.
   * *Registry*: Select the ACR created in Step 3.
   * *Image*: `azure-finsecops`.
   * *Tag*: `v1.0`.
   * *CPU & Memory*: `0.5 vCPU, 1.0 GiB`.
   * *Environment variables*: Add `AI_PROVIDER`, `GROQ_API_KEY`, `APP_HOST=0.0.0.0`, `APP_PORT=8000`.
5. **Ingress Tab**:
   * Check **Enable Ingress**.
   * *Ingress traffic*: `Accepting traffic from anywhere` (External).
   * *Target port*: `8000`.
6. Click **Review + Create**, then click **Create**.
7. Once deployed, click **Go to resource** and find the **Application Url** on the Overview screen.

---

## Future Enhancement: Attaching a Custom Domain with Free SSL/TLS

When you are ready in the future to connect your own company or personal domain (for example: `finsecops.yourcompany.com` or `app.yourdomain.com`), follow these exact steps:

### Part 1: Choose Your Hostname
Decide what domain name you want to use:
* Example subdomain: `finsecops.mycompany.com`
* Note your default Azure FQDN: e.g. `azure-finsecops-app.delightfulglade-XXXX.eastus.azurecontainerapps.io`

### Part 2: Add DNS Records at Your Domain Registrar (GoDaddy, Namecheap, Cloudflare, etc.)
Log in to your DNS provider dashboard and add two DNS records:

| Record Type | Name (Host) | Value / Target | Purpose |
| :--- | :--- | :--- | :--- |
| **CNAME** | `finsecops` | `azure-finsecops-app.delightfulglade-XXXX.eastus.azurecontainerapps.io` | Routes web traffic to your Azure container |
| **TXT** | `asuid.finsecops` | `<YOUR_CUSTOM_DOMAIN_VERIFICATION_ID>` | Proves to Azure that you own this domain |

> *To find your Custom Domain Verification ID*: In Azure Container Apps -> Settings -> **Custom domains**, look at the top for **Custom domain verification ID**.

### Part 3: Bind the Domain & Enable Free Managed Certificate
You do **not** need to buy an SSL certificate! Azure Container Apps generates a free, auto-renewing certificate via DigiCert.

#### Option A: In the Azure Portal
1. Navigate to your Container App (`azure-finsecops-app`).
2. In the left navigation menu under **Settings**, click **Custom domains**.
3. Click **+ Add custom domain**.
4. In **Domain**, type your subdomain: `finsecops.mycompany.com`.
5. In **Certificate**, select **Managed certificate** (100% Free).
6. Click **Validate**. Once the green checkmark appears confirming DNS propagation, click **Add**.

#### Option B: Via Azure CLI
```powershell
# 1. Add hostname to your app
az containerapp hostname add `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --hostname "finsecops.mycompany.com"

# 2. Issue and bind a free Managed Certificate
az containerapp hostname bind `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --hostname "finsecops.mycompany.com" `
  --environment $ENVIRONMENT_NAME `
  --validation-method CNAME
```

Now, visiting `https://finsecops.mycompany.com` serves your Azure FinSecOps platform over encrypted HTTPS with an automatic SSL lock icon.

---

## Troubleshooting & Pro-Tips

### 1. How to View Live Server Logs
To stream logs live as requests come in:
```powershell
az containerapp logs show `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --follow
```
Or in the Azure Portal, go to **Monitoring** -> **Log stream**.

### 2. "502 Bad Gateway" or Health Check Failure
* **Cause**: Flask is listening on `127.0.0.1` instead of `0.0.0.0`, or target port is not `8000`.
* **Fix**: Ensure your `app.py` has `host="0.0.0.0"` and Container App ingress target port is `8000`. (This is already pre-configured for you in our latest code updates!).

### 3. Update Environment Variables or API Keys
If you switch LLM providers or change your API key:
```powershell
az containerapp update `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --set-env-vars AI_PROVIDER="openai" OPENAI_API_KEY="<NEW_KEY>" OPENAI_MODEL="gpt-4o"
```

### 4. How to Delete Resources When Not in Use (Clean Up)
If you ever want to remove all resources to avoid any billing:
```powershell
az group delete --name $RESOURCE_GROUP --yes --no-wait
```
This cleanly deletes the Container App, Environment, Container Registry, and all associated disks in a single step.
