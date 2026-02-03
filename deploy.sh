#!/bin/bash
set -e

# Configuration
SERVICE_NAME="snappwd-service"
REGION="us-central1"

# Check for gcloud
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud CLI is not installed."
    echo "Please install the Google Cloud SDK: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

echo "🚀 Deploying $SERVICE_NAME to Google Cloud Run..."

# Prompt for Project ID if not set in environment or gcloud config
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null)
if [ -z "$CURRENT_PROJECT" ]; then
    read -p "Enter Google Cloud Project ID: " PROJECT_ID
else
    echo "Using project: $CURRENT_PROJECT"
    PROJECT_ID=$CURRENT_PROJECT
fi

# Prompt for Redis URL
echo "📝 Configuration"
read -p "Enter Redis URL (e.g., redis://host:6379): " REDIS_URL

if [ -z "$REDIS_URL" ]; then
    echo "❌ Error: Redis URL is required."
    exit 1
fi

echo "📦 Deploying from source..."
gcloud run deploy "$SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-env-vars "REDIS_URL=$REDIS_URL,MAX_FILE_SIZE_MB=5"

echo "✅ Deployment complete!"
