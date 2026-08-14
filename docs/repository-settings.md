# Recommended GitHub Repository Settings

Apply these after creating the remote repository.

## Default branch

- `main`
- require pull requests before merge once collaboration starts;
- require CI checks;
- require branches to be up to date when practical;
- block force pushes and branch deletion;
- prefer squash merge and linear history.

## Security

Enable:

- Dependabot alerts and security updates;
- secret scanning and push protection;
- CodeQL/code scanning;
- private vulnerability reporting;
- dependency graph.

## Actions

- default `GITHUB_TOKEN` permission: read-only;
- allow only required actions;
- keep Dependabot enabled for GitHub Actions updates;
- review permission changes in workflow PRs carefully.

## Discussions and issues

Enable Discussions for research/design questions. Keep security reports out of public issues.

See also [`github-bootstrap.md`](github-bootstrap.md) for first-push commands.
