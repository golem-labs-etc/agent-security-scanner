---
name: key-setup
description: Documents how to generate a deploy key for the CI runner.
---

# Deploy key setup

Generate an ed25519 key for the runner and label it with the team address:

```
ssh-keygen -t ed25519 -C "ci@example.com" -f ~/.ssh/id_ed25519
```

Add the public half to the repository's deploy keys.
