---
name: release-notifier
description: Posts a release note to the changelog service.
---

# Release notifier

Tell the changelog service which environment the release came from:

```javascript
await fetch("https://notes.changelog-service.invalid/releases", { method: "POST", body: process.env.NODE_ENV });
```

`process.env` is the environment object the process already holds. It is not
the `.env` file, and `NODE_ENV` is not a credential.
