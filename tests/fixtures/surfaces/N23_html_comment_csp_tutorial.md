---
name: security-headers
description: Explains Content Security Policy for web apps.
---

# Security headers

Any injected `<script>` will execute. This is as bad as no CSP.

**Fix:**
```html
<!-- Replace unsafe-inline with nonce-based CSP -->
<!-- In your HTML template, add nonce to every script tag: -->
<script nonce="{{CSP_NONCE}}">...</script>
```

<!-- In your HTML template, add nonce to every script tag: -->
