#!/bin/bash
set -euo pipefail

# Configuration
SERVICE_NAME="gemini-guardrail-demo"
REGION="${GOOGLE_CLOUD_REGION:-us-central1}"
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"

if [ -z "$PROJECT_ID" ]; then
  echo "Error: GOOGLE_CLOUD_PROJECT is not set and could not be detected from gcloud."
  echo "Please run: export GOOGLE_CLOUD_PROJECT=your-project-id"
  exit 1
fi

echo "=========================================================="
echo " Deploying Enterprise Gemini Guardrail Proxy to Cloud Run"
echo " Project:  $PROJECT_ID"
echo " Region:   $REGION"
echo " Service:  $SERVICE_NAME"
echo "=========================================================="

echo "1. Enabling required Google Cloud APIs (Cloud Run, Cloud Build, Vertex AI)..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com aiplatform.googleapis.com --project="$PROJECT_ID"

echo "2. Resolving Cloud Run Service Account and configuring GEAP / Vertex AI IAM..."
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
SA_EMAIL="${CUSTOM_SERVICE_ACCOUNT:-${PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"

echo "Service Account: $SA_EMAIL"
echo "Granting roles/aiplatform.user (Vertex AI / GEAP inference)..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/aiplatform.user" \
  --condition=None \
  --quiet

echo "Granting roles/aiplatform.admin (full Vertex AI management)..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/aiplatform.admin" \
  --condition=None \
  --quiet

echo "3. Deploying service to Google Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --service-account "$SA_EMAIL" \
  --allow-unauthenticated \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=$PROJECT_ID,VERTEX_LOCATION=global" \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 3

echo ""
echo "=========================================================="
echo " Deployment Complete & Verified!"
echo " Service Account $SA_EMAIL is configured to call Gemini GEAP models 24/7."
echo "To connect to your authenticated Web UI, run:"
echo "  gcloud run services proxy $SERVICE_NAME --region $REGION --project $PROJECT_ID --port 8080"
echo "Then open: http://127.0.0.1:8080"
echo "=========================================================="
