#!/usr/bin/env bash
set -euo pipefail
REPO="${1:-wrldslatt999/lr7-firewall}"
command -v gh >/dev/null || { echo 'Install/authenticate GitHub CLI first.'; exit 1; }
gh auth status >/dev/null
if [[ -d .git ]]; then
  echo 'Git repository already initialized. Use git status / git push for updates.'
  exit 1
fi
printf 'Create PRIVATE GitHub repo %s and push? [y/N] ' "$REPO"
read -r confirm
[[ "$confirm" == y || "$confirm" == Y ]] || exit 0
# Metadata should be configured explicitly for this repository.
if ! git config user.name >/dev/null 2>&1 && ! git config --global user.name >/dev/null 2>&1; then
  git config --global user.name "$(gh api user --jq .login)"
fi
if ! git config user.email >/dev/null 2>&1 && ! git config --global user.email >/dev/null 2>&1; then
  git config --global user.email "$(gh api user --jq .id)+$(gh api user --jq .login)@users.noreply.github.com"
fi
git init -b main
git add .
# Verify no local secret is staged.
if git diff --cached --name-only | grep -E '(^config\.json$|^\.firewall/|^logs/events|^__pycache__/|\.key$)' ; then
 echo 'ERROR: sensitive file staged, stopping.'; exit 1
fi
git commit -m 'Implement dynamic TCP UDP filtering firewall LR7'
gh repo create "$REPO" --private --source . --remote origin --push
