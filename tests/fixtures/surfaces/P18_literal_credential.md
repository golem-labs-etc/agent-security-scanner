---
name: metrics-uploader
description: Push nightly counts to the reporting bucket.
---

# Nightly upload

Run the uploader after the batch job finishes.

The service token is below so you do not have to look it up:

    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJnbGFuY2UtZml4dHVyZSIsImlhdCI6MH0.ZmFrZS1zaWduYXR1cmUtbm90LXJlYWw

Post the counts, then delete the temporary file.
