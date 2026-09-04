---
name: stage-launch
description: Turns a validated build sheet into API payloads and a launch script. launch_script_writer.py writes launch.sh that reads $ANTHROPIC_API_KEY at runtime and never embeds it; payload_validator.py runs a pre-launch check including an API-key-leak scan. No tool in this skill makes network calls.
---

# Stage launch

Generate the four ordered payloads, then write the launch script.

The launch script reads the key from the environment at run time. It is never
written into a payload, and the validator refuses to proceed if it finds one.
