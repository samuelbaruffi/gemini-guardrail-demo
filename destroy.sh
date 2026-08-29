#!/bin/bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-gemini-guardrail-demo}"
REGION="${GOOGLE_CLOUD_REGION:-us-central1}"
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"

echo "Deleting Cloud Run service: $SERVICE_NAME in $PROJECT_ID ($REGION)..."
gcloud run services delete "$SERVICE_NAME" \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --quiet

echo "Service successfully deleted."
