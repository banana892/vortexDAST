# CI/CD Integration

VortexDAST exits with code **2** when any HIGH/CRITICAL finding survives filtering,
and **0** otherwise, so a pipeline can gate on results. It also exports SARIF for
code-scanning dashboards. Only scan targets you are authorised to test.

## GitHub Actions

See [`.github/workflows/scan.yml`](../.github/workflows/scan.yml) for a ready-to-run
example that scans a target and uploads SARIF to GitHub Code Scanning. It is
manual-trigger (`workflow_dispatch`) so it never runs against an unintended target.

To create issues from findings instead of (or alongside) SARIF, set a
`GITHUB_TOKEN` and add:

```bash
vortex -u "$TARGET" --github-repo "$OWNER/$REPO" --issue-min-severity high
```

## GitLab CI

```yaml
dast:
  image: python:3.12
  rules:
    - if: $CI_PIPELINE_SOURCE == "web"   # manual, so you choose the target
  variables:
    TARGET: "https://staging.example.com"
  script:
    - pip install -e .
    - vortex -u "$TARGET" -o gl-dast-report.json || true
  artifacts:
    when: always
    paths:
      - gl-dast-report.json
```

## Jenkins (declarative pipeline)

```groovy
pipeline {
  agent { docker { image 'python:3.12' } }
  parameters { string(name: 'TARGET', defaultValue: '', description: 'URL to scan') }
  stages {
    stage('DAST') {
      steps {
        sh 'pip install -e .'
        sh 'vortex -u "$TARGET" -o report.html'  // non-zero exit fails the build on HIGH/CRITICAL
      }
    }
  }
  post { always { archiveArtifacts artifacts: 'report.html', allowEmptyArchive: true } }
}
```

## Jira export

For any runner, with `JIRA_API_TOKEN` set in the environment:

```bash
vortex -u "$TARGET" \
  --jira-url "https://your.atlassian.net" \
  --jira-user "you@example.com" \
  --jira-project SEC \
  --issue-min-severity high
```

## Speeding up pipeline runs

- `--incremental` reuses a cached crawl when the target/scope is unchanged
  (cache the `.vortex_crawl_cache.json` file between runs).
- `--group-endpoints` collapses value-only duplicate endpoints on large targets.
