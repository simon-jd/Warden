#!/usr/bin/env bash
set -eu
exec codex --no-alt-screen --no-daemon -C /home/postedism/Desktop/Warden -m gpt-6.1-sol -c 'model_reasoning_effort="xhigh"' --enable goals --approve-for-me -c sandbox_workspace_write.network_access=true -c 'projects."/home/postedism/Desktop/Warden".trust_level="trusted"'
