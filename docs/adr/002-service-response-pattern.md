# ADR-002: ServiceResponse Pattern

## Status
Accepted

## Context

We needed a consistent way to handle success/failure across service methods. The challenges:

1. **Error handling inconsistency** - Some methods throw exceptions, others return null, others return tuples
2. **HTTP status mapping** - Need to map business outcomes to appropriate HTTP status codes
3. **Metadata transport** - Some operations need to return additional data (e.g., JWT tokens)
4. **Client consistency** - API consumers should get predictable response shapes

Common alternatives:
- **Exceptions everywhere** - Throw for all errors, catch in middleware
- **Result<T> pattern** - Discriminated union style (Success | Failure)
- **Tuple returns** - Return `(T? data, string? error)`
- **Nullable returns** - Return null on failure

## Decision

We will use a `ServiceResponse<T>` wrapper for all service method returns:

```csharp
public class ServiceResponse<T>
{
    public T? Data { get; set; }
    public bool Success => StatusCode < 400;
    public int StatusCode { get; set; } = 200;
    public string Message { get; set; } = string.Empty;
    public Dictionary<string, object>? Metadata { get; set; }
}
```

**Key design choices**:
- `Success` is computed from `StatusCode` (< 400 = success)
- `Metadata` dictionary allows returning extra data (tokens, pagination, etc.)
- No exceptions for business logic failures; exceptions reserved for unexpected errors

**Creating responses via `ServiceResponseFactory`**:

Services should use `ServiceResponseFactory` to create responses rather than manual instantiation:
```csharp
public static class ServiceResponseFactory
{
    public static ServiceResponse<T> Success<T>(T data, string? message = null);
    public static ServiceResponse<T> Success<T>(string message);
    public static ServiceResponse<T> Error<T>(string message, int status = 400);
    public static ServiceResponse<T> Error<T>(string message, T data, int status = 400);
    public static ServiceResponse<T> NotFound<T>(string message);
}
```

**Controller resolution via `BaseAppController`**:
```csharp
protected async Task<IActionResult> ResolveAsync<T>(
    Func<Task<ServiceResponse<T>>> function)
{
    var response = await function();
    return StatusCode(response.StatusCode, response);
}
```

## Consequences

### Positive

- **Consistent API responses** - Every endpoint returns the same shape
- **Explicit error handling** - Can't accidentally ignore errors (unlike nullable)
- **HTTP status clarity** - Status code is part of the response, not an afterthought
- **Metadata flexibility** - Can attach tokens, pagination info, etc. without changing signature
- **No exception overhead** - Business failures don't incur exception cost

### Negative

- **Verbosity** - Every service method wraps return in `ServiceResponse`
- **Null checks still needed** - `Data` can be null even on success (e.g., 204 No Content)
- **Not idiomatic C#** - Some developers prefer exceptions or Result<T, E>

### Neutral

- **Constants for messages** - We use `ServiceResponseConstants` for standardized messages
- **Factory pattern** - `ServiceResponseFactory` provides fluent creation methods

## Usage Examples

### Success with data
```csharp
return ServiceResponseFactory.Success(userDto, "User retrieved successfully");
```

### Failure
```csharp
return ServiceResponseFactory.NotFound<UserDto>(ServiceResponseConstants.UserNotFound);
```

### Error with custom status
```csharp
return ServiceResponseFactory.Error<UserDto>("Validation failed", status: 422);
```

## Alternatives Considered

### Exceptions Only
Rejected because:
- Performance overhead for expected failures (invalid credentials, not found)
- Exceptions should be exceptional, not control flow
- Harder to return partial success or warnings

### Result<T, E> (Discriminated Union)
Considered but rejected because:
- C# doesn't have native discriminated unions (would need library like OneOf)
- Pattern matching syntax more verbose in C# than F#
- Less familiar to typical .NET developers

### Tuple Returns
Rejected because:
- Easy to ignore error component
- No standardized shape for API responses
- Doesn't carry HTTP status code naturally

## References

- [Railway Oriented Programming](https://fsharpforfunandprofit.com/rop/)
- [Problem Details RFC 7807](https://datatracker.ietf.org/doc/html/rfc7807) (considered for error responses)