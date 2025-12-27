---
title: Observability
nav_order: 8
---

# Observability & Logging

Starbase includes enterprise-grade observability with structured logging and distributed tracing.

## Structured Logging with Serilog

### Configuration

```json
{
  "Serilog": {
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    },
    "Enrich": ["FromLogContext"]
  }
}
```

### Development

Console output enabled automatically in development:

```csharp
var loggerConfig = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext();

if (builder.Environment.IsDevelopment())
{
    loggerConfig.WriteTo.Console();
}

Log.Logger = loggerConfig.CreateLogger();
```

### Production Configuration

```json
{
  "Serilog": {
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    },
    "WriteTo": [
      {
        "Name": "File",
        "Args": {
          "path": "/var/log/starbase/app-.log",
          "rollingInterval": "Day",
          "retainedFileCountLimit": 7,
          "formatter": "Serilog.Formatting.Compact.CompactJsonFormatter, Serilog.Formatting.Compact"
        }
      },
      {
        "Name": "ApplicationInsights",
        "Args": {
          "connectionString": "your-connection-string"
        }
      }
    ],
    "Enrich": ["FromLogContext"],
    "Properties": {
      "Application": "Starbase",
      "Environment": "Production"
    }
  }
}
```

### Custom Logging Components

**LogContextHelper** – Structured context building:

```csharp
logger.Info(new StructuredLogBuilder()
    .SetAction(AuthActions.Login)
    .SetStatus(LogStatuses.Success)
    .SetTarget(AuthTargets.User(username))
    .SetEntity(nameof(AppUser))
    .SetDetail("User authenticated successfully"));
```

## OpenTelemetry

### Instrumentation Coverage

- **ASP.NET Core** – HTTP request/response tracing
- **HTTP Client** – Outbound HTTP call tracing
- **SQL Client** – Database operation tracing
- **Custom traces** – Application-specific with source "StarbaseTemplateAPI"

### Configuration

```csharp
services.AddOpenTelemetry()
    .WithTracing(tracing =>
    {
        tracing
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddSqlClientInstrumentation()
            .AddSource("StarbaseTemplateAPI")
            .AddOtlpExporter();

        if (environment.IsDevelopment())
        {
            tracing.AddConsoleExporter();
        }
    })
    .WithMetrics(metrics => metrics
        .AddAspNetCoreInstrumentation());
```

### Environment Variables

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://your-collector:4317
OTEL_SERVICE_NAME=starbase-api
OTEL_RESOURCE_ATTRIBUTES=service.version=1.0.0,deployment.environment=production
```

### Custom Tracing

Add custom traces in your services:

```csharp
using var activity = ActivitySource.StartActivity("CustomOperation");
activity?.SetTag("user.id", userId);
activity?.SetTag("operation.type", "mfa-verification");
// Your business logic here
```

## Log Correlation

- **Request IDs** – Automatically correlate logs across components
- **User context** – Enriches logs for audit trails
- **Exception context** – Detailed error information

## Integration Options

| Platform | Setup |
|----------|-------|
| **Azure Application Insights** | Add Serilog.Sinks.ApplicationInsights |
| **ELK Stack** | Add Serilog.Sinks.Elasticsearch |
| **Splunk** | Add Serilog.Sinks.Splunk |
| **Seq** | Add Serilog.Sinks.Seq |
| **Jaeger** | Configure OTLP exporter |
| **Grafana/Tempo** | Configure OTLP exporter |
| **DataDog** | Configure OTLP exporter |

## Best Practices

1. **Use structured logging** – Always use templated messages
2. **Don't log sensitive data** – Passwords, tokens, PII
3. **Configure appropriate log levels** – Reduce noise in production
4. **Set up alerting** – Monitor for errors and anomalies
5. **Correlate with traces** – Link logs to distributed traces
6. **Retain logs appropriately** – Consider compliance requirements