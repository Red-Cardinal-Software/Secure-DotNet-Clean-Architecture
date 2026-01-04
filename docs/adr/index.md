# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Starbase template. ADRs document significant architectural decisions, providing context for why certain approaches were chosen.

## What is an ADR?

An ADR captures an important architectural decision made along with its context and consequences. They help:

- **New team members** understand why things are the way they are
- **Future maintainers** know what constraints existed when decisions were made
- **Users of the template** decide if they need to deviate from the defaults

## ADR Index

| ID | Title | Status | Date |
|----|-------|--------|------|
| [001](001-clean-architecture.md) | Clean Architecture | Accepted | 2024-12 |
| [002](002-service-response-pattern.md) | ServiceResponse Pattern | Accepted | 2024-12 |
| [003](003-sql-server-ledger-audit.md) | SQL Server Ledger for Immutable Audit | Accepted | 2024-12 |
| [004](004-unit-of-work-crud-operator.md) | Unit of Work with CrudOperator | Accepted | 2024-12 |
| [005](005-jwt-key-rotation.md) | JWT Signing Key Rotation | Accepted | 2024-12 |
| [006](006-compliance-presets.md) | Compliance Presets | Accepted | 2024-12 |

## ADR Template

When adding a new ADR, use this template:

```markdown
# ADR-XXX: Title

## Status
Accepted | Superseded | Deprecated

## Context
What is the issue that we're seeing that is motivating this decision or change?

## Decision
What is the change that we're proposing and/or doing?

## Consequences
What becomes easier or more difficult to do because of this change?

### Positive
- Benefit 1
- Benefit 2

### Negative
- Trade-off 1
- Trade-off 2

### Neutral
- Side effect 1
```

## When to Write an ADR

Write an ADR when:
- Making a decision that affects the structure of multiple components
- Choosing between multiple viable approaches
- The decision would be questioned by a new team member
- You're overriding or extending a decision from a previous ADR