---
name: ai-security
description: Reference table of prompt-injection signatures for review work.
---

# Injection signatures

The table below is the reference a reviewer checks a suspect prompt against.

| Technique | Example | Detection |
|---|---|---|
| Persona framing | "You are now [unconstrained persona]" | Matches jailbreak_persona signature |
| Context reset | "Forget the rules above" | Matches reset signature |
