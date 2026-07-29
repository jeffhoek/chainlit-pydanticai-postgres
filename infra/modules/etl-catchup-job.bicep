// Ad-hoc ETL catch-up job: a MANUAL-trigger Container Apps Job for large one-off
// backlogs (e.g. an SSVC "storm" backfill of ~344k records) and other catch-ups
// that would time out the laptop or overrun the scheduled job's window.
//
// It is a near-clone of the scheduled job (modules/etl-job.bicep) — same image,
// managed identity, ACR pull, and Key Vault secrets — with two deliberate
// differences:
//   1. triggerType 'Manual' (no cron): it only runs when started explicitly, via
//      `az containerapp job start` from the ETL pipeline (azure-pipelines-etl.yml).
//   2. A much larger replicaTimeout (default 10h) so a multi-hour incremental
//      catch-up or embedding backfill can finish without being terminated. The
//      per-start override in `az containerapp job start` cannot change
//      replicaTimeout, so the ceiling must live on the definition here.
//
// The pipeline overrides `command`/`args` per start to select the run mode
// (load_nvd_full.py --incremental / --backfill-embeddings / --backfill-ssvc,
// run_etl.py, or load_kev.py). The command/args below are only a safe default for
// a hand-run `az containerapp job start` with no overrides.

param location string
param managedEnvironmentId string
param jobName string
param identityId string
param identityClientId string
param acrLoginServer string
param keyVaultName string

@description('ACS endpoint for the results email (https://<host>). Used only by the run_etl.py mode; the load_nvd_full.py modes do not email.')
param acsEndpoint string

@description('Verified ACS sender address for the results email.')
param acsSender string

@description('Comma-separated recipient address(es) for the results email.')
param emailTo string

@description('Max seconds a catch-up run may take before it is terminated. Default 10h — large backfills are long. Raise if an embedding backfill needs more.')
param replicaTimeout int = 36000

@description('CPU cores for the catch-up replica. Matches the scheduled job by default.')
param cpu string = '1.0'

@description('Memory for the catch-up replica.')
param memory string = '2.0Gi'

param tags object = {}

var imageRef = '${acrLoginServer}/vulncopilot:latest'
var kvBase = 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/secrets'

// Reuses the environment created by the scheduled job's module (passed in as
// managedEnvironmentId) so we do not stand up a second Container Apps Environment
// or Log Analytics workspace — one environment hosts both jobs.
resource catchupJob 'Microsoft.App/jobs@2024-03-01' = {
  name: jobName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentId
    configuration: {
      triggerType: 'Manual'
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
      replicaTimeout: replicaTimeout
      // No automatic retry: a partial catch-up is better restarted deliberately
      // (with --since) than silently retried from a mutated high-water mark.
      replicaRetryLimit: 0
      registries: [
        {
          server: acrLoginServer
          identity: identityId
        }
      ]
      secrets: [
        {
          name: 'openai-api-key'
          keyVaultUrl: '${kvBase}/openai-api-key'
          identity: identityId
        }
        {
          name: 'database-url'
          keyVaultUrl: '${kvBase}/database-url'
          identity: identityId
        }
        {
          name: 'nvd-api-key'
          keyVaultUrl: '${kvBase}/nvd-api-key'
          identity: identityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'etl-catchup'
          image: imageRef
          // Safe default for a bare `az containerapp job start` with no override;
          // the pipeline replaces command/args per run to pick the mode.
          command: [
            '/app/.venv/bin/python'
            'scripts/load_nvd_full.py'
          ]
          args: [
            '--incremental'
          ]
          resources: {
            cpu: json(cpu)
            memory: memory
          }
          env: [
            {
              name: 'OPENAI_API_KEY'
              secretRef: 'openai-api-key'
            }
            {
              name: 'PG_DATABASE_URL'
              secretRef: 'database-url'
            }
            {
              name: 'NVD_API_KEY'
              secretRef: 'nvd-api-key'
            }
            // Identifies the user-assigned identity for DefaultAzureCredential (ACS auth,
            // used only by the run_etl.py mode).
            {
              name: 'AZURE_CLIENT_ID'
              value: identityClientId
            }
            {
              name: 'ACS_ENDPOINT'
              value: acsEndpoint
            }
            {
              name: 'ACS_SENDER'
              value: acsSender
            }
            {
              name: 'ETL_EMAIL_TO'
              value: emailTo
            }
          ]
        }
      ]
    }
  }
}

output jobName string = catchupJob.name
