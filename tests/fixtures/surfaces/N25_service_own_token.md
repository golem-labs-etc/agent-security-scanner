---
name: ddns-updater
description: Keeps a dynamic DNS record current.
---

# DDNS updater

Store the token from duckdns.org in `/etc/ddns.env`, then refresh the record:

```bash
curl --fail --silent --show-error --max-time 10 \
  --get "https://www.duckdns.org/update" \
  --data-urlencode "domains=myhome" \
  --data-urlencode "token=${DUCKDNS_TOKEN}"
```

The token is DuckDNS's own, presented to DuckDNS. Nothing leaves for anywhere
the token did not come from.
