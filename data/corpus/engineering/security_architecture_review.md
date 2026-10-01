# Security Architecture Review (2026-Q1)

## Network segmentation
Production runs in three zones: edge, application and data. East-west traffic between
application services requires mutual TLS with a 24 hour certificate lifetime. Data zone access
is limited to a documented allow-list reviewed each quarter.

## Key management
Customer data encryption keys are stored in the managed HSM. The service principal for the
signing key is restricted to four named engineers and rotates every 90 days. Break-glass
credentials are held in escrow and require two-person approval.

## Recovery and backup
Backups are encrypted with a separate key and replicated to a second region. Point-in-time
recovery is validated monthly; the last restore drill took 47 minutes against a 2 hour objective.

## Weaknesses accepted
Legacy reporting database still permits password authentication from the data zone. Remediation
is scheduled for 2026-Q3. Compensating controls: network allow-list and 15 minute session limits.
