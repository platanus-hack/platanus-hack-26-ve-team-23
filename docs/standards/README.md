# Engineering standards

How work is done in this repository. The reasons behind the larger rules are
recorded as [ADRs](../adr/README.md).

| Standard | What it covers |
|---|---|
| [Development workflow](development-workflow.md) | Branch lifecycle, local checks, push policy |
| [Git and pull requests](git-and-pull-requests.md) | Branch names, commit messages, pull requests, reviews |
| [Code and testing](code-and-testing.md) | Conventions per component, where tests live |
| [Security and dependencies](security-and-dependencies.md) | Secrets, vulnerabilities, new dependencies |
| [Documentation](documentation.md) | Where things are written, language |

## Principles

- **Keep it simple.** We have days, not months. Build what the demo and the
  evaluation need.
- **Measure, then claim.** No number in the pitch that the evaluation did not
  produce.
- **Fail closed.** When the Guardian is unsure or unreachable, deny.
- **Readable over clever.** Judges and reviewers will read the security
  claims; make that easy.
