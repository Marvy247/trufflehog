#!/bin/bash
set -e

exec ./scanner \
  -github-token "$GITHUB_TOKEN" \
  -webhook-url "$WEBHOOK_URL" \
  -verify-online
