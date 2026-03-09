#!/usr/bin/env bash
# Create GCP Secret Manager secrets and grant access to the Cloud Run service account.
# Usage: ./scripts/create-gcp-secrets.sh

set -euo pipefail

PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [[ -z "$PROJECT_ID" ]]; then
  echo "Error: No GCP project set. Run: gcloud config set project YOUR_PROJECT_ID" >&2
  exit 1
fi

SERVICE_ACCOUNT="chatbot-runner@${PROJECT_ID}.iam.gserviceaccount.com"

SECRETS=(
  ANTHROPIC_API_KEY
  OPENAI_API_KEY
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  APP_PASSWORD
  APP_USERNAME
  CHAINLIT_AUTH_SECRET
)

echo "Project: ${PROJECT_ID}"
echo "Service account: ${SERVICE_ACCOUNT}"
echo

for SECRET in "${SECRETS[@]}"; do
  read -rsp "Enter value for ${SECRET}: " VALUE
  echo

  if [[ -z "$VALUE" ]]; then
    echo "  Skipping ${SECRET} (empty value)"
    continue
  fi

  echo -n "$VALUE" | gcloud secrets create "$SECRET" --data-file=-

  gcloud secrets add-iam-policy-binding "$SECRET" \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet > /dev/null

  echo "  Created ${SECRET} and granted access"
done

echo
echo "Done. All secrets are ready."
