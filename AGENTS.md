# AGENTS.md

## Workflow Rules

1. After each successful feature, bugfix, or meaningful adjustment, create an automatic git commit.
2. Use clear commit scopes, e.g. `fix:`, `feat:`, `docs:`, `chore:`.
3. For critical or high-risk changes (auth, DB migrations, security controls, destructive operations):
   - create a dedicated branch (for example `critical/<topic>`),
   - validate behavior,
   - request user confirmation that results are as expected,
   - merge into `main` only after confirmation.
4. Never commit secrets, tokens, private keys, or real production IP inventories.
5. Keep public artifacts anonymized by default (IPs, hostnames, usernames, internal paths).

## Standard Git Commands

```bash
git add -A
git commit -m "<type>: <short description>"
```

Critical path:

```bash
git checkout -b critical/<topic>
# implement + test
git add -A
git commit -m "<type>: <critical change>"
# after user confirms:
git checkout main
git merge --no-ff critical/<topic>
```
