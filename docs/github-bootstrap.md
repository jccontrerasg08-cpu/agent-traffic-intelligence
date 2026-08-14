# GitHub Bootstrap

The source tree is ready to publish, but creating the remote repository is an account-level action and is intentionally separate from the source bootstrap.

## Create the public repository

Recommended repository name:

`agent-traffic-intelligence`

Do not initialize the remote with a README, license, or `.gitignore`; those already exist locally.

With GitHub CLI from the repository directory:

```bash
gh repo create jccontrerasg08-cpu/agent-traffic-intelligence \
  --public \
  --source=. \
  --remote=origin \
  --push
```

Or create an empty public repository in the GitHub web UI, then:

```bash
git remote add origin git@github.com:jccontrerasg08-cpu/agent-traffic-intelligence.git
git push -u origin main
```

HTTPS alternative:

```bash
git remote add origin https://github.com/jccontrerasg08-cpu/agent-traffic-intelligence.git
git push -u origin main
```

## Immediately after first push

Apply the recommendations in [`repository-settings.md`](repository-settings.md), especially:

- read-only default `GITHUB_TOKEN` permissions;
- secret scanning and push protection;
- Dependabot alerts and security updates;
- CodeQL/code scanning;
- private vulnerability reporting;
- branch protection or rulesets once CI has completed successfully;
- squash merge and linear history for routine contributions.

## First checks

After the first push, confirm these workflows are green:

1. `CI`
2. `CodeQL`

`Dependency Review` runs on pull requests.

Then open a small documentation PR to verify the branch-protection workflow before making protection mandatory.
