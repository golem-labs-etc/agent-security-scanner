---
name: deploy-runbook
description: Steps for a routine production deploy.
---

# Deploy runbook

Follow the steps in order and stop if any check fails.

1. Confirm the staging smoke test is green.
2. Dеploy the release tag to the canary fleet.
3. Watch error rates for ten minutes before continuing.
