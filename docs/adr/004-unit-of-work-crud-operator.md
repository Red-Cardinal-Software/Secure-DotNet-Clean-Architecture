# ADR-004: Unit of Work with CrudOperator Pattern

## Status
Accepted

## Context

We needed a data access pattern that:

1. **Separates concerns** - Generic CRUD vs domain-specific queries
2. **Enables transactions** - Multiple operations commit atomically
3. **Avoids repetition** - Don't rewrite Add/Update/Delete in every repository
4. **Maintains testability** - Easy to mock for unit tests
5. **Follows composition over inheritance** - No deep class hierarchies

Common patterns:
- **Generic Repository<T>** - Base class with virtual methods
- **Repository per aggregate** - Each aggregate root gets a repository
- **CQRS** - Separate read/write models
- **Direct DbContext** - Inject DbContext everywhere

## Decision

We will use a **composition-based pattern** with three components:

### 1. ICrudOperator<T>
Generic CRUD operations, injected into repositories:
```csharp
public interface ICrudOperator<TEntity> where TEntity : class
{
    IQueryable<TEntity> GetAll();
    void Delete(TEntity entity);
    void DeleteMany(IEnumerable<TEntity> entities);
    Task AddAsync(TEntity entity, CancellationToken ct = default);
    Task AddManyAsync(IEnumerable<TEntity> entities, CancellationToken ct = default);
}
```

### 2. Domain-Specific Repositories
Compose with CrudOperator, add domain queries:
```csharp
public class AppUserRepository(ICrudOperator<AppUser> crudOperator) : IAppUserRepository
{
    public Task<AppUser?> GetByUsernameAsync(string username) =>
        crudOperator.GetAll()
            .FirstOrDefaultAsync(u => u.Username == username);

    public Task AddAsync(AppUser user) =>
        crudOperator.AddAsync(user);
}
```

### 3. IUnitOfWork
Transaction coordination:
```csharp
public interface IUnitOfWork
{
    Task<int> CommitAsync(CancellationToken ct = default);
}
```

### Service Usage
Services inherit from `BaseAppService` and use `RunWithCommitAsync` to wrap operations that modify data. This automatically commits on success:

```csharp
public class AppUserService(
    IAppUserRepository userRepository,
    IUnitOfWork unitOfWork) : BaseAppService(unitOfWork)
{
    // Expression-bodied style - preferred for conciseness
    public async Task<ServiceResponse<UserDto>> CreateUserAsync(CreateUserDto dto) =>
        await RunWithCommitAsync(async () =>
        {
            var user = new AppUser(...);
            await userRepository.AddAsync(user);
            return ServiceResponseFactory.Success(MapToDto(user));
        });

    // Updates happen automatically via EF change tracking
    public async Task<ServiceResponse<UserDto>> UpdateUserAsync(Guid id, UpdateUserDto dto) =>
        await RunWithCommitAsync(async () =>
        {
            var user = await userRepository.GetByIdAsync(id);
            user.UpdateFrom(dto);  // Entity is now modified
            // No explicit Update call needed - CommitAsync persists changes
            return ServiceResponseFactory.Success(MapToDto(user));
        });
}
```

## Consequences

### Positive

- **No inheritance hierarchy** - Repositories compose with CrudOperator, don't inherit
- **Focused repositories** - Only contain domain-specific query methods
- **DRY CRUD** - Add/Delete/Update implemented once in CrudOperator
- **Flexible transactions** - UnitOfWork.CommitAsync() controls when changes persist
- **Easy testing** - Mock ICrudOperator to test repository logic without database
- **IQueryable power** - Repositories build on GetAll(), full LINQ support

### Negative

- **Two concepts to understand** - CrudOperator vs Repository can confuse newcomers
- **No explicit Update** - EF Core change tracking handles updates implicitly
- **UnitOfWork is thin** - Only has CommitAsync; no Rollback (EF handles via disposal)

### Neutral

- **BaseAppService.RunWithCommitAsync** - Automatically commits after successful service operations
- **No repository access via UnitOfWork** - Repositories injected separately, not accessed via `unitOfWork.Users`

## Design Rationale

### Why composition over inheritance?

Inheritance-based approach:
```csharp
public class AppUserRepository : Repository<AppUser>, IAppUserRepository
{
    // Inherits Add, Update, Delete, GetAll from base
    // Overrides are awkward, base class grows over time
}
```

Composition approach (what we chose):
```csharp
public class AppUserRepository(ICrudOperator<AppUser> crud) : IAppUserRepository
{
    // Explicitly calls crud.AddAsync, crud.GetAll()
    // Clear what's happening, easy to customize
}
```

### Isn't DbContext already a Unit of Work?

Yes. EF Core's `DbContext` is itself a Unit of Work implementation - it tracks changes and commits them atomically via `SaveChangesAsync()`. Our `IUnitOfWork` is a thin wrapper that provides:

- **Abstraction** - Services don't directly depend on EF types
- **Testability** - Simpler to mock than DbContext
- **Consistent pattern** - `RunWithCommitAsync` standardizes how services commit changes

This is a convenience, not a necessity. Teams comfortable with EF could inject `DbContext` directly:

```csharp
// Alternative: Direct DbContext injection
public class AppUserService(AppDbContext db)
{
    public async Task<ServiceResponse<UserDto>> CreateAsync(CreateUserDto dto)
    {
        var user = new AppUser(...);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return ServiceResponseFactory.Success(MapToDto(user));
    }
}
```

We chose the abstraction for consistency and to keep services ORM-agnostic, but acknowledge it's a stylistic choice.

### Why no explicit Update method?

EF Core's change tracking handles updates:
```csharp
var user = await repository.GetByIdAsync(id);
user.UpdateEmail(newEmail);  // Entity is now modified
await unitOfWork.CommitAsync();  // Changes persisted
```

Adding `UpdateAsync(entity)` would be redundant and misleading.

### Why IQueryable in GetAll()?

EF Core uses **deferred execution** - queries aren't sent to the database until enumerated (e.g., `ToListAsync()`, `FirstOrDefaultAsync()`). Returning `IQueryable<T>` allows repositories to compose queries that execute as a single optimized SQL statement:

```csharp
public Task<List<AppUser>> GetActiveUsersInOrganization(Guid orgId) =>
    crudOperator.GetAll()
        .Where(u => u.Active)
        .Where(u => u.OrganizationId == orgId)
        .OrderBy(u => u.Username)
        .ToListAsync();  // Query executes HERE, not before
```

This produces a single SQL query with `WHERE Active = 1 AND OrganizationId = @orgId ORDER BY Username`, rather than loading all users into memory and filtering in C#.

## Alternatives Considered

### Generic Repository Base Class
Rejected because:
- Deep inheritance hierarchies become rigid
- Harder to customize behavior per repository
- "Favor composition over inheritance" principle

### CQRS with MediatR Handlers
Considered but not default because:
- Adds complexity for simple CRUD operations
- Better suited for complex domains with many behaviors
- Can be added by users who need it (MediatR is included for domain events)

### Direct DbContext Injection
Rejected because:
- Repositories provide abstraction over data access
- Harder to test services (need to mock DbContext)
- Business logic can leak into services

## References

- [Martin Fowler - Unit of Work](https://martinfowler.com/eaaCatalog/unitOfWork.html)
- [Composition over Inheritance](https://en.wikipedia.org/wiki/Composition_over_inheritance)