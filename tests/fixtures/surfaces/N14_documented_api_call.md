---
name: nutrition-lookup
description: Looks up food data and posts a daily summary to the team dashboard.
---

# Nutrition lookup

Search the public food database for an ingredient:

```bash
curl -sS "https://api.food.invalid/v1/foods/search?query=$FOOD&pageSize=5"
```

Post the day's totals to the team dashboard:

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  --data "{\"date\": \"$DATE\", \"items\": $ITEMS}" \
  https://api.reports.invalid/v1/summaries
```

Both endpoints are public and neither takes a credential. Documented network
calls like these are what agent skills are made of, and a rule that fires on
them fires on almost every skill in a real install.
