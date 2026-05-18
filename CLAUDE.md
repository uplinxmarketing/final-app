# Uplinx Meta Manager — Claude Instructions

## Git workflow (ALWAYS follow this)

After completing any set of changes:

1. Commit all changed files to `claude/replace-app-uplinx-meta-g7hsg` with a clear commit message
2. Push to `origin claude/replace-app-uplinx-meta-g7hsg`
3. If the branch has merge conflicts with main, rebase onto main first
4. Create a pull request targeting `main` in the `uplinxmarketing/ad-upload` repo
5. Immediately merge the PR using squash merge
6. Every change must end up on `main` — never leave work only on the feature branch

Do this automatically at the end of every task without being asked.

## version.txt — CRITICAL RULE

`version.txt` is marked `skip-worktree` locally (`git update-index --skip-worktree version.txt`).
This means local edits to it are NEVER committed and NEVER pushed.

**After every PR merge to main**, bump version.txt on GitHub using `mcp__github__create_or_update_file`
targeting `main` with the next version number (r1 → r2 → r3 etc.).

You need the current SHA of version.txt from GitHub to do the update — get it from the previous
`create_or_update_file` response or from `mcp__github__get_file_contents`.

**NEVER** use the `Write` or `Edit` tools on `version.txt`.
**NEVER** include `version.txt` in a `git add` or `git commit`.
The only valid way to change it is via `mcp__github__create_or_update_file` on the `main` branch.

This ensures the user's installed version always lags behind GitHub so the update check works.
