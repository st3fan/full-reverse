# Project

The project and command are named `full-reverse`.

This is a reverse-DNS (PTR) lookup tool for IPv4 addresses, CIDR ranges, and
ASNs. It uses RIPE Stat to resolve AS names and announced prefixes, and writes
results as JSONL to stdout. Progress and diagnostics go to stderr.

The tool is written in Go. See [README.md](README.md) for usage and behavior.

# Method of working

1. Plan the work in a GitHub issue. Describe the proposed changes, scope, and validation, and have the user review the issue before implementation.
2. Implement the reviewed plan in a pull request for simple work.
3. For complicated work, use a stack of pull requests. Split the work into focused, reviewable layers, with foundational changes below the changes that depend on them. Create the stack before implementing its layers.
4. Link the pull request or stack to the planning issue and explain how the changes were validated.
5. When the user asks to merge a pull request, treat the work as complete. After merging, switch back to the repository's default branch and update it from the remote so the next task starts there. Preserve any unrelated local changes.

Use the repository's [gh-stack skill](.agents/skills/gh-stack/SKILL.md) to manage stacked pull requests. Read and follow the skill before creating or modifying a stack.

# Validation

For code changes, build and validate before requesting review:

```sh
go build -o full-reverse .
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Format changed Go files with `gofmt`. Update the README when command-line
options, output, or user-visible behavior changes. Record any validation that
could not be completed and the reason in the pull request.
