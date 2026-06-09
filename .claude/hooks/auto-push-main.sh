#!/usr/bin/env bash
# Stop hook: commit any pending work, push the working branch, and fast-forward
# `main` to it so every task lands on the deploy branch automatically.
# Always exits 0 so it can never block or loop the session.
set -uo pipefail

# Move to the repo root (CLAUDE_PROJECT_DIR is set by the harness).
cd "${CLAUDE_PROJECT_DIR:-.}" 2>/dev/null || exit 0
root="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
cd "$root" || exit 0

branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)" || exit 0
# Skip if detached HEAD or no branch.
[ -z "$branch" ] && exit 0
[ "$branch" = "HEAD" ] && exit 0

msg=""

# 1. Commit pending changes, if any.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  git add -A 2>/dev/null
  if git commit -m "Auto-commit pending work [stop hook]" >/dev/null 2>&1; then
    msg="committed; "
  fi
fi

# 2. Push the working branch.
git push -u origin "$branch" >/dev/null 2>&1 && msg="${msg}pushed ${branch}; "

# 3. Fast-forward main to the working branch (only if it stays a clean FF).
if [ "$branch" != "main" ]; then
  git fetch origin main >/dev/null 2>&1
  if git merge-base --is-ancestor origin/main "$branch" 2>/dev/null; then
    if git push origin "${branch}:main" >/dev/null 2>&1; then
      msg="${msg}main updated ✅"
    else
      msg="${msg}main push FAILED ❌"
    fi
  else
    msg="${msg}main NOT updated — diverged, needs manual merge ⚠️"
  fi
else
  msg="${msg}already on main"
fi

# Report back to the user via the Stop hook's systemMessage channel.
printf '{"systemMessage":"Auto-push to main: %s"}\n' "${msg:-nothing to do}"
exit 0
