# Contributing to Kuta

Thank you for your interest in contributing to Kuta! 🎉

We welcome contributions from everyone. This document will guide you through the process.

## Table of Contents

- [Contributing to Kuta](#contributing-to-kuta)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [How Can I Contribute?](#how-can-i-contribute)
    - [Reporting Bugs](#reporting-bugs)
    - [Suggesting Features](#suggesting-features)
  - [Contributing Code](#contributing-code)
  - [Branch Organization](#branch-organization)
  - [Commit Message Format](#commit-message-format)
  - [Project Structure](#project-structure)
  - [License](#license)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to:

- ✅ Be respectful and inclusive
- ✅ Focus on what's best for the community
- ✅ Show empathy towards others
- ✅ Accept constructive criticism gracefully
- ❌ Don't harass, troll, or discriminate

Please read and follow our [Code of Conduct](https://github.com/lborres/kuta/blob/main/CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

Before creating a bug report:
1. Check existing [Issues](https://github.com/lborres/kuta/issues) to avoid duplicates
2. Collect information about the bug (version, steps to reproduce, error messages)

**Create a bug report with:**

> **Describe the bug**
> A clear description of what the bug is.
>
> **To Reproduce**
> Steps to reproduce the behavior:
> 1. Go to '...'
> 2. Click on '...'
> 3. See error
>
> **Expected behavior**
> What you expected to happen.
>
> **Environment:**
> - OS: [e.g., Ubuntu 22.04]
> - Go version: [e.g., 1.25.4]
> - Kuta version: [e.g., v0.1.0]
>
> **Additional context**
> Any other relevant information.

### Suggesting Features
Before suggesting a feature:

- Check if it's already suggested
- Consider if it fits Kuta's scope (authentication framework)

**Create a feature request with:**
> **Problem Statement**
> What problem does this solve?
>
> **Proposed Solution**
> How would you like it to work?
>
> **Alternatives Considered**
> What other solutions did you think of?
>
> **Additional Context**
> Examples, mockups, or references.

## Contributing Code
Areas we'd love help with:
- [ ] Bug fixes
- [ ] Database Adapters (MySQL, SQLite, MongoDB, etc.)
- [ ] Web framework adapters (Echo, Chi, Gin)
- [ ] Documentation improvements
- [ ] Example applications
- [ ] Test coverage improvements
- [ ] Performance optimizations

## Branch Organization
Code that lands in main must be compatible with the latest stable release. It may contain additional features, but no breaking changes. We should be able to release a new minor version from the tip of main at any time.

## Commit Message Format
Please see the [Conventional Commits Specifications](https://www.conventionalcommits.org/en/v1.0.0/).
Also, read [AngularJS commit message format](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format) for additional information.

We use the [Conventional Commits Specifications](https://www.conventionalcommits.org/en/v1.0.0/) to enable a number of automation solutions such as auto generated changelogs and determining a semantic version bump.

Commit message format:
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `test` - Test changes
- `refactor` - Code refactoring
- `perf` - Performance improvements
- `chore` - Maintenance tasks

**Scopes:**
- `core` - Core authentication logic
- `fiber` - Fiber adapter
- `postgres` - PostgreSQL adapter
- `examples` - Example code
- `ci` - CI/CD changes


## Project Structure
```
/kuta
├── core/           # Framework-agnostic logic (no external dependencies)
├── adapters/       # Database and HTTP adapters
├── examples/       # Example applications
```

## License
By contributing to the Kuta project, you agree that your contributions will be licensed under the project's stated [LICENSE](https://github.com/lborres/kuta/blob/main/LICENSE.md).
