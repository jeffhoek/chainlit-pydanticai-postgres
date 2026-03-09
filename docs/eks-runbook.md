# EKS Deployment Runbook — chainlit-pydanticai-rag

This runbook covers deploying the Chainlit + Pydantic AI RAG chatbot to an AWS EKS cluster using GitHub Actions CI/CD.

---

## Architecture Overview

```
GitHub (push to main)
    ↓
[Build Job]
  • OIDC → AWS credentials (no long-lived keys)
  • docker build → push to ECR (tag: commit SHA)
    ↓
[Deploy Job]
  • Check EKS cluster health (skips gracefully if down)
  • kubectl apply k8s/ manifests
  • Rolling update with new image
  • Wait for rollout (120s timeout)
    ↓
AWS EKS (eks-proto, us-east-2)
  └─ Namespace: rag
      ├─ Deployment: chainlit-rag (1 replica)
      ├─ Service: ClusterIP (port 80 → 8080)
      └─ Ingress: ALB (internet-facing, sticky sessions)
           ↓
      Chainlit app (port 8080)
        • Loads knowledge base from S3 on startup
        • Generates embeddings (OpenAI)
        • In-memory vector store (NumPy)
        • Pydantic AI agent → Claude (Anthropic)
```

### Why 1 Replica?

The vector store is held in memory per-pod. Multiple pods would each hold an independent copy — acceptable with ALB sticky sessions — but starting with 1 replica simplifies the initial deployment. Scale up once you've validated the deployment.

### WebSocket Considerations

Chainlit uses WebSockets. The ALB is configured with:
- **600-second idle timeout** — exceeds Chainlit's session keep-alive to prevent mid-chat drops
- **24-hour sticky sessions** — ensures each browser always routes to the same pod (required for WebSocket state)

---

## Prerequisites

### Tools

| Tool | Purpose | Install |
|------|---------|---------|
| `aws` CLI v2 | ECR login, EKS kubeconfig, IAM | https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html |
| `kubectl` | Apply manifests, check pod status | `brew install kubectl` |
| `eksctl` | IAM identity mapping for RBAC | `brew install eksctl` |
| `docker` or `podman` | Local image build/test | `brew install podman` |
| `uv` | Generate Chainlit auth secret | already in project |

### AWS Requirements

- EKS cluster `eks-proto` is **ACTIVE** in `us-east-2`
- ECR repository `chainlit-pydanticai-rag` exists (created in setup below)
- AWS CLI configured with sufficient permissions for setup steps

### GitHub Repository Requirements

- Repository is in GitHub (not just local)
- You have access to **Settings → Secrets and variables → Actions**

---

## One-Time Setup

### Step 1 — Create ECR Repository

```bash
aws ecr create-repository \
  --repository-name chainlit-pydanticai-rag \
  --region us-east-2
```

Note the registry URI from the output (format: `<account-id>.dkr.ecr.us-east-2.amazonaws.com`).

### Step 2 — Configure GitHub OIDC Provider in AWS

This allows GitHub Actions to assume an IAM role without storing long-lived AWS credentials.

```bash
# Check if OIDC provider already exists (may already be set up from another deployed application)
aws iam list-open-id-connect-providers | grep token.actions.githubusercontent.com
```

If not listed, create it:

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

The deploy role ARN follows a fixed format, so you can add the GitHub Actions secret now — before the role exists. All you need is your account ID:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "arn:aws:iam::${ACCOUNT_ID}:role/github-actions-chainlit-rag" | pbcopy
```

In your GitHub repository:
1. Go to **Settings → Secrets and variables → Actions**
2. Click **New repository secret**
3. Name: `AWS_DEPLOY_ROLE_ARN`
4. Value: paste the ARN copied above

### Step 3 — Create the IAM Deploy Role

An IAM role has two independent parts: a **trust policy** that controls *who* can assume the role, and **permission policies** that control *what* the role can do once assumed. This step handles the first part — creating the role and scoping assumption to GitHub Actions OIDC tokens from this repository. Permissions are attached in Step 4.

Replace `<your-github-org>` with your GitHub org or username.

```bash
GITHUB_ORG=<your-github-org>
REPO_NAME=chainlit-pydanticai-rag
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

- Write a trust policy document scoping role assumption to GitHub Actions OIDC tokens from this repo
```
cat > /tmp/trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:${GITHUB_ORG}/${REPO_NAME}:*"
        }
      }
    }
  ]
}
EOF
```

- Create the IAM role using the trust policy
```
aws iam create-role \
  --role-name github-actions-chainlit-rag \
  --assume-role-policy-document file:///tmp/trust-policy.json
```

### Step 4 — Attach Permissions to the Deploy Role

With the role created, attach the policies that define what it's authorized to do. These are evaluated independently of the trust policy — a caller must satisfy *both* to successfully use the role.

- Attach the ECR PowerUser managed policy to allow the role to push and pull images
```
aws iam attach-role-policy \
  --role-name github-actions-chainlit-rag \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser
```

- Write an inline policy granting the role permission to describe EKS clusters (needed to fetch kubeconfig)
```
cat > /tmp/eks-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters"
      ],
      "Resource": "*"
    }
  ]
}
EOF
```

- Attach the EKS inline policy to the role
```
aws iam put-role-policy \
  --role-name github-actions-chainlit-rag \
  --policy-name eks-describe \
  --policy-document file:///tmp/eks-policy.json
```

### Step 5 — Grant the Deploy Role kubectl Access

Add the IAM role to the EKS cluster's `aws-auth` ConfigMap, mapping it to a Kubernetes user with `system:masters` (cluster-admin) access so the GitHub Actions workflow can run `kubectl` commands.

```bash
eksctl create iamidentitymapping \
  --cluster eks-proto \
  --region us-east-2 \
  --arn arn:aws:iam::${ACCOUNT_ID}:role/github-actions-chainlit-rag \
  --username github-actions \
  --group system:masters
```

> **Note:** `system:masters` is the simplest way to grant full cluster access for CI/CD. For tighter security, create a custom ClusterRole limited to the `rag` namespace.

### Step 6 — Create the Kubernetes Namespace and Secrets

```bash
# Update your kubeconfig to point at eks-proto
aws eks update-kubeconfig --name eks-proto --region us-east-2
```

- Create the `rag` namespace in the cluster
```
kubectl apply -f k8s/namespace.yaml
```

- Create the ServiceAccount that EKS Pod Identity will bind the S3 role to
```
kubectl apply -f k8s/serviceaccount.yaml
```

- Generate a Chainlit session signing secret and copy the output for the next command
```
uv run chainlit create-secret
# → something like: CHAINLIT_AUTH_SECRET="abc123..."
```

- Create the Kubernetes secret containing all app credentials and config values
```bash
echo "ANTHROPIC_API_KEY" && read -s ANTHROPIC_API_KEY
echo "OPENAI_API_KEY" && read -s OPENAI_API_KEY
echo "APP_PASSWORD" && read -s APP_PASSWORD \
echo "CHAINLIT_AUTH_SECRET" && read -s CHAINLIT_AUTH_SECRET \
echo "S3_BUCKET" && read -s S3_BUCKET \
echo "S3_KEY" && read -s S3_KEY
```

Or equivalently with a loop:

```bash
for var in ANTHROPIC_API_KEY OPENAI_API_KEY APP_PASSWORD CHAINLIT_AUTH_SECRET S3_BUCKET S3_KEY; do
  echo "$var" && read -rs $var
done
```

```
kubectl create secret generic rag-secrets \
  --namespace rag \
  --from-literal=ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  --from-literal=OPENAI_API_KEY=$OPENAI_API_KEY \
  --from-literal=APP_PASSWORD=$APP_PASSWORD \
  --from-literal=CHAINLIT_AUTH_SECRET=$CHAINLIT_AUTH_SECRET \
  --from-literal=S3_BUCKET=$S3_BUCKET \
  --from-literal=S3_KEY=$S3_KEY
```

> `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are not stored as secrets — S3 access uses EKS Pod Identity instead. See Step 7.

### Step 7 — Configure EKS Pod Identity for S3 Access

The `eks-pod-identity-agent` addon injects temporary AWS credentials into pods via a ServiceAccount-to-IAM-role binding, eliminating the need for static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` credentials.

#### Create the S3 IAM role

- Write a trust policy allowing EKS Pod Identity to assume the role
```
cat > /tmp/pod-identity-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "pods.eks.amazonaws.com" },
    "Action": ["sts:AssumeRole", "sts:TagSession"]
  }]
}
EOF
```

- Create the role
```
aws iam create-role \
  --role-name chainlit-rag-s3 \
  --assume-role-policy-document file:///tmp/pod-identity-trust.json
```

- Write an inline policy granting read access to your S3 bucket
```
S3_BUCKET=<your-bucket-name>
cat > /tmp/s3-read-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::${S3_BUCKET}",
      "arn:aws:s3:::${S3_BUCKET}/*"
    ]
  }]
}
EOF
```

- Attach the policy to the role
```
aws iam put-role-policy \
  --role-name chainlit-rag-s3 \
  --policy-name s3-read \
  --policy-document file:///tmp/s3-read-policy.json
```

#### Create the PodIdentityAssociation

Link the `chainlit-rag` Kubernetes ServiceAccount (applied in Step 6) to the IAM role:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws eks create-pod-identity-association \
  --cluster-name eks-proto \
  --region us-east-2 \
  --namespace rag \
  --service-account chainlit-rag \
  --role-arn arn:aws:iam::${ACCOUNT_ID}:role/chainlit-rag-s3
```

The EKS Pod Identity Agent automatically injects temporary credentials into any pod using the `chainlit-rag` ServiceAccount. No service account annotations are required.

---

## Deploying

Once the one-time setup is complete, deployments happen automatically:

- **Auto-deploy**: push any commit to `main`
- **Manual trigger**: GitHub → Actions → "Deploy to EKS" → "Run workflow"

The workflow:
1. Builds a Docker image tagged with the commit SHA
2. Pushes to ECR
3. Checks the EKS cluster is active (skips deploy gracefully if not)
4. Applies all `k8s/` manifests
5. Does a rolling update (`kubectl set image`) to the new image
6. Waits up to 120s for rollout to complete

---

## Post-Deploy Verification

- Watch pod status until `Ready` (startup can take 30-60s while embeddings are generated)
```bash
kubectl get pods -n rag -w
```

- Stream logs to confirm successful startup
```bash
kubectl logs -n rag deploy/chainlit-rag --follow
```

- Get the ALB hostname from the `HOSTS` column
```bash
kubectl get ingress -n rag
```

- Confirm the app is healthy
```bash
curl http://<alb-hostname>/healthz
# Expected: {"status":"ok"}
```

- Open in browser — log in with `APP_USERNAME` / `APP_PASSWORD`
```bash
open http://<alb-hostname>
```

---

## Rollback

- Roll back to the previous deployment
```bash
kubectl rollout undo deployment/chainlit-rag -n rag
```

- To roll back to a specific revision, first list available revisions
```bash
kubectl rollout history deployment/chainlit-rag -n rag
```

- Then roll back to the chosen revision
```bash
kubectl rollout undo deployment/chainlit-rag -n rag --to-revision=<N>
```

---

## Troubleshooting

### Pod stuck in `Pending`

```bash
kubectl describe pod -n rag -l app=chainlit-rag
```
Common causes: insufficient node resources, image pull error (check ECR permissions), or no nodes available.

### Pod stuck in `Init` / slow to become `Ready`

Expected behavior — the app fetches data from S3 and generates embeddings on startup. The `startupProbe` allows up to **120 seconds** before marking the pod unhealthy. If it's taking longer:

```bash
kubectl logs -n rag deploy/chainlit-rag
# Look for: data loading, embedding progress, or error messages
```

If S3 access fails, the app falls back to the local `data/` directory baked into the image.

### Image pull errors

```bash
kubectl describe pod -n rag -l app=chainlit-rag | grep -A5 Events
```
Ensure the ECR repository exists and the deploy role has `AmazonEC2ContainerRegistryPowerUser`.

### WebSocket disconnects mid-chat

Check the ALB idle timeout. If users are seeing disconnects, confirm the ingress annotation is set to `idle_timeout.timeout_seconds=600`.

### Updating secrets

Kubernetes secrets are not automatically reloaded by running pods. After updating:

```bash
kubectl delete secret rag-secrets -n rag
kubectl create secret generic rag-secrets --namespace rag \
  --from-literal=ANTHROPIC_API_KEY=<new-value> \
  # ... all other values
kubectl rollout restart deployment/chainlit-rag -n rag
```

### Scaling up replicas

The in-memory vector store is rebuilt independently per pod. With ALB sticky sessions, each user session stays on one pod. Scale up once validated:

```bash
kubectl scale deployment chainlit-rag -n rag --replicas=2
```

---

## Environment Variables Reference

### Stored as Kubernetes Secret (`rag-secrets`)

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key |
| `OPENAI_API_KEY` | OpenAI API key for embeddings |
| `APP_PASSWORD` | Chainlit login password |
| `CHAINLIT_AUTH_SECRET` | Chainlit session signing secret (`chainlit create-secret`) |
| `S3_BUCKET` | S3 bucket containing the knowledge base |
| `S3_KEY` | S3 object key for the knowledge base file |

> S3 credentials are not stored here — the pod acquires temporary AWS credentials automatically via EKS Pod Identity (see Step 7).

### Stored as Kubernetes ConfigMap (`rag-config`)

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_USERNAME` | `admin` | Chainlit login username |
| `AWS_REGION` | `us-east-2` | AWS region for S3 |
| `LLM_MODEL` | `anthropic:claude-haiku-4-5-20251001` | Pydantic AI model string |
| `TOP_K` | `5` | Number of chunks returned by RAG retrieval |
| `SYSTEM_PROMPT` | _(see configmap)_ | System prompt injected into the Pydantic AI agent |
