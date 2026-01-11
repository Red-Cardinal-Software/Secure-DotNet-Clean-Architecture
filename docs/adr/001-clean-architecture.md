# ADR-001: Clean Architecture

## Status
Accepted

## Context

We needed to choose an architectural pattern for structuring the API template. The goals were:

1. **Testability** - Business logic should be testable without infrastructure dependencies
2. **Flexibility** - Should be easy to swap databases, frameworks, or external services
3. **Maintainability** - New developers should quickly understand where code belongs
4. **Security Focus** - Security concerns should be isolated and auditable

Common alternatives considered:
- **N-Tier/Layered Architecture** - Simple but often leads to tight coupling
- **Vertical Slice Architecture** - Good for CQRS but can lead to duplication
- **Hexagonal/Ports & Adapters** - Similar to Clean Architecture, slightly different terminology
- **Clean Architecture** - Dependency inversion with clear boundaries

## Decision

We will use **Clean Architecture** with four primary layers:

```
┌─────────────────────────────────────────────────────────────┐
│  WebApi (Presentation)                                      │
│  Controllers, Middleware, API Configuration                 │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure                                             │
│  EF Core, Repositories, External Services, Security Impl    │
├─────────────────────────────────────────────────────────────┤
│  Application                                                │
│  Services, DTOs, Interfaces, Validation, Use Cases          │
├─────────────────────────────────────────────────────────────┤
│  Domain                                                     │
│  Entities, Value Objects, Domain Events, Exceptions         │
└─────────────────────────────────────────────────────────────┘
```

**Dependency Rule**: Dependencies point inward. Domain has no dependencies. Application depends only on Domain. Infrastructure and WebApi depend on Application (and transitively, Domain).

**Additional Projects**:
- `DependencyInjectionConfiguration` - Centralized DI setup (keeps WebApi clean)
- `TestUtils` - Shared test builders and utilities

## Consequences

### Positive

- **Domain stays pure** - No EF Core attributes, no framework dependencies in entities
- **Easy to test** - Services depend on interfaces, easily mocked
- **Database agnostic** - Repository interfaces in Application, implementations in Infrastructure
- **Security isolation** - All security implementations (hashing, JWT, etc.) in Infrastructure
- **Clear boundaries** - New developers know where to put code

### Negative

- **More projects** - 9 projects vs 2-3 for a simple API
- **More interfaces** - Every service needs an interface for testability
- **Mapping overhead** - DTOs ↔ Entities requires mapping code
- **Initial learning curve** - Developers unfamiliar with Clean Architecture need onboarding

### Neutral

- **Not "pure" Clean Architecture** - We don't have explicit Use Case classes; services contain use case logic
- **AutoMapper optional** - We provide it but also support manual mapping via DI, ie 'IAppUserMapper -> AppuserMapper'

## Alternatives Considered

### Vertical Slice Architecture
Rejected because:
- Better suited for CQRS-heavy applications
- Can lead to code duplication across slices
- Harder to enforce consistent security patterns across slices

### Simple N-Tier
Rejected because:
- Typically leads to business logic leaking into controllers or data access
- Harder to test without spinning up real database
- Tighter coupling makes swapping components difficult

## References

- [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Microsoft's Clean Architecture guidance](https://docs.microsoft.com/en-us/dotnet/architecture/modern-web-apps-azure/common-web-application-architectures#clean-architecture)