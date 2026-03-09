# Deploying to Google Cloud Run

This guide walks through deploying the RAG chatbot to Google Cloud Run.

## Prerequisites

- [Google Cloud CLI (`gcloud`)](https://cloud.google.com/sdk/docs/install) installed and authenticated
- A GCP project with billing enabled
- Your `.env` file configured locally (see the main [README](../README.md))
- Docker or Podman for local testing (optional)

## 1. GCP Project Setup

Set your project and enable required APIs:

```bash
gcloud config set project YOUR_PROJECT_ID
```

```bash
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com
```

## 2. Service Accounts

Cloud Build uses the default Compute Engine service account. Verify it exists:

```bash
gcloud builds get-default-service-account
```

Create a dedicated service account for Cloud Run with least-privilege access:

```bash
gcloud iam service-accounts create chatbot-runner \
  --display-name="RAG Chatbot Cloud Run SA"
```

## 3. Secrets Management

Store sensitive values in Secret Manager rather than passing them as plain environment variables.

### Individual commands (reference)

Create a secret:

```bash
echo -n "VALUE" | gcloud secrets create SECRET_NAME --data-file=-
```

Grant the Cloud Run service account access to it:

```bash
gcloud secrets add-iam-policy-binding SECRET_NAME \
  --member="serviceAccount:chatbot-runner@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### Create all secrets at once

Run the included helper script to be prompted for each secret value. It creates the secret and grants access to the Cloud Run service account in one step:

```bash
./scripts/create-gcp-secrets.sh
```

### Update a secret value later

```bash
echo -n "new-value" | gcloud secrets versions add SECRET_NAME --data-file=-
```

## 4. Prepare Non-Secret Environment Variables

Cloud Run accepts non-secret environment variables from a YAML file. Use the included helper script to generate it from your `.env`:

```bash
./scripts/env2yaml.sh .env > .env.yaml
```

Then **edit `.env.yaml`** to remove all secret values (API keys, passwords, credentials). Only keep non-secret configuration like:

```yaml
AWS_REGION: "us-east-1"
S3_BUCKET: "your-bucket-name"
S3_KEY: "path/to/your/data.txt"
TOP_K: "5"
LLM_MODEL: "anthropic:claude-haiku-4-5-20251001"
SYSTEM_PROMPT: "You are a helpful assistant. Use the retrieve tool to..."
```

> `.env.yaml` is already in `.gitignore` so it won't be committed.

## 5. Deploy

```bash
gcloud run deploy chainlit-pydanticai-rag \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080 \
  --memory 1Gi \
  --timeout 300 \
  --session-affinity \
  --min-instances 0 \
  --max-instances 3 \
  --env-vars-file .env.yaml \
  --build-service-account projects/YOUR_PROJECT_ID/serviceAccounts/YOUR_PROJECT_NUMBER-compute@developer.gserviceaccount.com \
  --set-secrets="ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:latest,OPENAI_API_KEY=OPENAI_API_KEY:latest,AWS_ACCESS_KEY_ID=AWS_ACCESS_KEY_ID:latest,AWS_SECRET_ACCESS_KEY=AWS_SECRET_ACCESS_KEY:latest,APP_PASSWORD=APP_PASSWORD:latest,APP_USERNAME=APP_USERNAME:latest,CHAINLIT_AUTH_SECRET=CHAINLIT_AUTH_SECRET:latest" \
  --service-account chatbot-runner@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

### Key flags explained

| Flag | Purpose |
|------|---------|
| `--source .` | Build the container from the Dockerfile in the current directory |
| `--session-affinity` | Routes a client to the same instance across requests (required for Chainlit's WebSocket connections) |
| `--min-instances 0` | Scale to zero when idle to reduce cost |
| `--max-instances 3` | Cap the maximum number of instances |
| `--memory 1Gi` | Memory allocated per instance |
| `--timeout 300` | Request timeout in seconds (5 min, useful for long LLM responses) |
| `--allow-unauthenticated` | Makes the service publicly accessible (the app has its own login) |
| `--build-service-account` | Service account used during Cloud Build |
| `--set-secrets` | Maps Secret Manager secrets to environment variables |
| `--service-account` | Runtime service account with Secret Manager access |

On success, the CLI outputs the service URL:

```
Service URL: https://YOUR_SERVICE-YOUR_PROJECT_NUMBER.us-central1.run.app
```

## 6. Verify the Deployment

```bash
gcloud run services describe chainlit-pydanticai-rag \
  --region us-central1 \
  --format="value(status.url)"
```

Check logs if something isn't working:

```bash
gcloud run services logs read chainlit-pydanticai-rag \
  --region us-central1 \
  --limit 50
```

## 7. Redeploying

After code changes, run the same `gcloud run deploy` command from step 5. Cloud Build will rebuild the container image and create a new revision.

To redeploy after changing only a secret value:

```bash
# Update the secret
echo -n "new-value" | gcloud secrets versions add SECRET_NAME --data-file=-

# Force a new revision to pick up the latest secret version
gcloud run services update chainlit-pydanticai-rag \
  --region us-central1
```

## Cleanup

To delete the Cloud Run service and avoid further charges:

```bash
gcloud run services delete chainlit-pydanticai-rag --region us-central1
```

To also remove the container images from Artifact Registry:

```bash
gcloud artifacts docker images list us-central1-docker.pkg.dev/YOUR_PROJECT_ID/cloud-run-source-deploy \
  --format="value(IMAGE)" | while read -r image; do
  gcloud artifacts docker images delete "$image" --quiet
done
```
