---
title: Docker
nav_order: 9
---

# Docker Support

Starbase includes production-ready Docker configuration for containerized deployments.

## Quick Start

### Full Stack (API + Database + Redis)

```bash
docker-compose up -d
```

This starts:
- **SQL Server 2022** on port 1433
- **Redis 7** on port 6379
- **Starbase API** on port 5000

### Dependencies Only

For local development with `dotnet run`:

```bash
docker-compose -f docker-compose.deps.yml up -d
```

Then run the API locally:

```bash
dotnet run --project WebApi
```

## Dockerfile

Multi-stage build optimized for production:

```dockerfile
# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files for layer caching
COPY *.sln ./
COPY Domain/Domain.csproj Domain/
COPY Application/Application.csproj Application/
# ... other projects

# Restore and build
RUN dotnet restore
COPY . .
RUN dotnet publish WebApi/WebApi.csproj -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Non-root user for security
RUN groupadd -r starbase && useradd -r -g starbase starbase
COPY --from=build /app/publish .
RUN chown -R starbase:starbase /app
USER starbase

EXPOSE 8080
ENTRYPOINT ["dotnet", "WebApi.dll"]
```

### Security Features

- **Multi-stage build** – Smaller image, no build tools in production
- **Non-root user** – Container runs as unprivileged user
- **Layer caching** – Project files copied first for faster rebuilds

## Docker Compose

### Full Stack Configuration

```yaml
version: '3.8'

services:
  sqlserver:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      - ACCEPT_EULA=Y
      - MSSQL_SA_PASSWORD=YourStrong!Passw0rd
      - MSSQL_PID=Developer
    ports:
      - "1433:1433"
    volumes:
      - sqlserver-data:/var/opt/mssql
    healthcheck:
      test: /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$$MSSQL_SA_PASSWORD" -Q "SELECT 1" -C
      interval: 10s
      retries: 10
      start_period: 30s

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  api:
    build: .
    ports:
      - "5000:8080"
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ConnectionStrings__SqlConnection=Server=sqlserver;Database=Starbase;...
      - AppSettings__JwtSigningKey=YourSecretKey...
    depends_on:
      sqlserver:
        condition: service_healthy
      redis:
        condition: service_healthy

volumes:
  sqlserver-data:
  redis-data:
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `ASPNETCORE_ENVIRONMENT` | Runtime environment | `Production`, `Development` |
| `ConnectionStrings__SqlConnection` | Database connection | `Server=...` |
| `ConnectionStrings__Redis` | Redis connection | `redis:6379` |
| `AppSettings__JwtSigningKey` | JWT signing key | 32+ character secret |
| `AppSettings__JwtIssuer` | Token issuer | `https://api.example.com` |
| `AppSettings__JwtAudience` | Token audience | `myapp-api-users` |

## Building

### Build Image

```bash
docker build -t starbase-api .
```

### Build with Custom Tag

```bash
docker build -t mycompany/myapi:1.0.0 .
```

### Build for Specific Platform

```bash
docker build --platform linux/amd64 -t starbase-api .
```

## Running

### Run with Existing Database

```bash
docker run -d \
  -p 5000:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e ConnectionStrings__SqlConnection="Server=myserver;..." \
  -e AppSettings__JwtSigningKey="your-secret-key" \
  starbase-api
```

### Run with Docker Network

```bash
# Create network
docker network create starbase-net

# Run SQL Server
docker run -d --name sqlserver --network starbase-net \
  -e ACCEPT_EULA=Y \
  -e MSSQL_SA_PASSWORD=YourStrong!Passw0rd \
  mcr.microsoft.com/mssql/server:2022-latest

# Run API
docker run -d --name api --network starbase-net \
  -p 5000:8080 \
  -e ConnectionStrings__SqlConnection="Server=sqlserver;..." \
  starbase-api
```

## Production Considerations

### Secrets Management

Never hardcode secrets in docker-compose files. Use:

- **Docker Secrets** (Swarm mode)
- **Environment files** (`.env`)
- **External secret managers** (Azure Key Vault, AWS Secrets Manager)

```bash
# Using .env file
docker-compose --env-file production.env up -d
```

### Health Checks

The API exposes health endpoints for container orchestration:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/api/health/live"]
  interval: 30s
  timeout: 10s
  retries: 3
```

Or use the wget alternative (available in base image):

```yaml
healthcheck:
  test: ["CMD-SHELL", "wget -q --spider http://localhost:8080/api/health/live || exit 1"]
```

### Resource Limits

```yaml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Logging

```yaml
services:
  api:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

## Kubernetes

For Kubernetes deployment, see the [Health Checks](health-checks.md#kubernetes-integration) documentation for probe configuration.

Basic deployment example:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: starbase-api
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: api
        image: starbase-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: ConnectionStrings__SqlConnection
          valueFrom:
            secretKeyRef:
              name: starbase-secrets
              key: sql-connection
        livenessProbe:
          httpGet:
            path: /api/health/live
            port: 8080
        readinessProbe:
          httpGet:
            path: /api/health/ready
            port: 8080
```