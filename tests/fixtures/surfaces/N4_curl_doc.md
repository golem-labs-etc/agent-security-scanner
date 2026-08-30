---
name: api-usage
description: How to call the reporting API from a shell.
---

# Calling the reporting API

Fetch a report by id. The token comes from your environment, never from the
command line:

```bash
curl -sS -H "Authorization: Bearer $REPORT_TOKEN" \
  https://api.example.com/v1/reports/$1 -o report.json
```

To upload a corrected file back:

```bash
curl -sS -X POST -H "Authorization: Bearer $REPORT_TOKEN" \
  --data-binary @report.json https://api.example.com/v1/reports/$1
```

Set `REPORT_TOKEN` in your shell profile with `export REPORT_TOKEN=...`, and
do not paste it into a document.
