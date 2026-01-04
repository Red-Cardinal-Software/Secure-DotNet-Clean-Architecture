---
title: Home
layout: home
nav_order: 1
---

# Starbase

## A Secure .NET Clean Architecture Template

A secure, extensible, and production-ready .NET template project built with clean architecture, Domain-Driven Design (DDD), and a strong focus on testability and maintainability.

## Purpose & Context

This template was created to serve as a security-first starting point for building production-grade .NET APIs.
It incorporates architectural and operational patterns that mitigate common vulnerabilities — including those often seen in on-premises and cloud environments — by enforcing secure defaults, strong authentication flows, and layered protections.

It was informed by years of practical experience in building and securing multi-tenant cloud applications.
The goal is to make it easier for teams to start secure rather than attempting to retrofit security into an existing codebase.

## Core Design Decisions

- **Short-lived access tokens + refresh tokens** — Minimizes risk from token theft.
- **Claims-based and role-based authorization** — Flexible, fine-grained access control.
- **Comprehensive rate limiting** — Protects against brute force attacks and API abuse with configurable IP-based throttling.
- **Guarded domain entities and value objects** — Prevent invalid state and enforce invariants.
- **FluentValidation everywhere** — Input is never trusted by default.
- **Dependency injection-first design** — Encourages testability and clear boundaries.
- **Separation of concerns via Clean Architecture** — Each layer has a single purpose.
- **Security-conscious defaults** — Connection strings secured, SQL uses least-privilege accounts, sensitive operations are audited.

## Features

- **Clean Architecture** (Domain, Application, Infrastructure, API)
- **Secure Auth Layer** with refresh tokens and short-lived access tokens
- **Multi-Factor Authentication (MFA)** with TOTP, WebAuthn/FIDO2, Email MFA, and recovery codes
- **Account Lockout Protection** with exponential backoff and configurable policies
- **Comprehensive Rate Limiting** with IP-based throttling and configurable policies
- **Enterprise Audit Logging** with tamper-evident hash chain and SQL Server Ledger
- **Production Health Check Endpoints** with privilege-based access controls
- **Validation with FluentValidation**, including async + injected validators
- **Docker Support** for containerized deployments
- **Unit of Work & Repository Patterns**
- **Value Objects and Guarded Entities**

## Project Structure

```bash
.
├── Application/                  # DTOs, Services, Validators, Interfaces
├── DependencyInjectionConfiguration/  # Centralized DI setup
├── Domain/                       # Core domain models and value objects
├── Infrastructure/               # EF Core, Repositories, Configurations
├── WebApi/                       # Controllers and API setup
├── *.Tests/                      # Unit and integration tests
```

## Technologies Used

- ASP.NET Core 8
- Entity Framework Core 9
- FluentValidation
- OAuth 2.0 with JWT and Refresh Tokens
- Microsoft.AspNetCore.RateLimiting (built-in .NET 8)
- Serilog (Structured Logging)
- OpenTelemetry (Distributed Tracing & Metrics)
- MediatR (Domain Events)
- SQL Server Ledger Tables (Tamper-evident auditing)
- xUnit + Moq + FluentAssertions
- Clean Architecture / Domain Driven Design

## Quick Start

See the [Getting Started](getting-started.md) guide for installation and first run instructions.

## API Examples

Ready-to-use API examples for testing and exploring endpoints:

- **[Postman Collection](api-examples/Starbase.postman_collection.json)** — Import into Postman for interactive testing
- **[.http Files](api-examples/)** — Use with VS Code REST Client or JetBrains IDEs

See the [API Examples README](api-examples/README.md) for setup instructions.

## License

This project is licensed under the MIT License.