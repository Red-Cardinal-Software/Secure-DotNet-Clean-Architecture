---
title: Health Checks
nav_order: 7
---

# Health Checks

Starbase includes production-ready health check endpoints designed for monitoring, load balancers, and container orchestration.

## Endpoints

| Endpoint | Access | Purpose | Rate Limited |
|----------|--------|---------|--------------|
| `/api/health` | Public | Basic health status | 30/min |
| `/api/health/detailed` | Public | Safe detailed status | 30/min |
| `/api/health/live` | Public | Liveness probe | 30/min |
| `/api/health/ready` | Public | Readiness probe | 30/min |
| `/api/health/system` | Privileged | Complete system metrics | 30/min |

## Configuration

```json
{
  "HealthChecks": {
    "MemoryThresholdMB": 1024,
    "IncludeMemoryCheck": false
  },
  "RateLimiting-Health-PermitLimit": "30",
  "RateLimiting-Health-WindowMinutes": "1"
}
```

## Response Examples

### Basic Health Check

`GET /api/health`

```json
{
  "status": "Healthy",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Detailed Health Check

`GET /api/health/detailed`

```json
{
  "status": "Healthy",
  "totalDuration": 45.2,
  "checks": [
    {
      "name": "database",
      "status": "Healthy",
      "duration": 42.1,
      "description": "Service operational"
    }
  ],
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### System Health Check (Privileged)

`GET /api/health/system`

Requires `SystemAdministration.Metrics` privilege.

```json
{
  "status": "Healthy",
  "totalDuration": 67.8,
  "checks": [
    {
      "name": "database",
      "status": "Healthy",
      "duration": 42.1,
      "description": "Service operational",
      "data": {}
    },
    {
      "name": "memory",
      "status": "Healthy",
      "duration": 1.2,
      "description": "Service operational",
      "data": {
        "memoryUsageMB": 512,
        "thresholdMB": 1024
      }
    }
  ],
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Status Codes

| Code | Meaning |
|------|---------|
| 200 OK | All health checks passed |
| 503 Service Unavailable | One or more checks failed |
| 429 Too Many Requests | Rate limit exceeded |

## Kubernetes Integration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: starbase-api
spec:
  template:
    spec:
      containers:
      - name: api
        image: starbase-api:latest
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /api/health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Adding Custom Health Checks

### 1. Create the Health Check

```csharp
public class RedisHealthCheck : IHealthCheck
{
    private readonly IConnectionMultiplexer _redis;

    public RedisHealthCheck(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var db = _redis.GetDatabase();
            await db.PingAsync();
            return HealthCheckResult.Healthy("Redis is responsive");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Redis is not responsive", ex);
        }
    }
}
```

### 2. Register the Health Check

```csharp
services.AddHealthChecks()
    .AddCheck<RedisHealthCheck>("redis",
        failureStatus: HealthStatus.Degraded,
        tags: new[] { "external", "ready" });
```

## Built-in Health Checks

### Database Health Check

- Tests database connectivity
- 5-second timeout protection
- Performance monitoring (warns if >1000ms)
- Never exposes connection strings
- Tagged for readiness probes

### Memory Health Check (Optional)

- Monitors managed memory usage
- Configurable threshold (default: 1024MB)
- Tagged as "privileged" for security
- Only available via `/api/health/system`

## Monitoring

```bash
# Check basic health
curl -f http://your-api.com/api/health

# Check readiness for load balancer
curl -f http://your-api.com/api/health/ready

# Check detailed status (authenticated)
curl -f -H "Authorization: Bearer $TOKEN" http://your-api.com/api/health/system
```