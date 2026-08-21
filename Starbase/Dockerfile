# Starbase API Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy solution and project files first (for better layer caching)
COPY Starbase.sln ./
# Central Package Management: package versions live here, so it must be present
# before `dotnet restore` runs or every PackageReference resolves with no version.
COPY Directory.Packages.props ./
COPY Domain/Domain.csproj Domain/
COPY Application/Application.csproj Application/
COPY Infrastructure/Infrastructure.csproj Infrastructure/
COPY DependencyInjectionConfiguration/DependencyInjectionConfiguration.csproj DependencyInjectionConfiguration/
COPY WebApi/WebApi.csproj WebApi/
COPY TestUtils/TestUtils.csproj TestUtils/
COPY Domain.Tests/Domain.Tests.csproj Domain.Tests/
COPY Application.Tests/Application.Tests.csproj Application.Tests/
COPY WebApi.Integration.Tests/WebApi.Integration.Tests.csproj WebApi.Integration.Tests/

# Restore dependencies
RUN dotnet restore

# Copy remaining source code
COPY Domain/ Domain/
COPY Application/ Application/
COPY Infrastructure/ Infrastructure/
COPY DependencyInjectionConfiguration/ DependencyInjectionConfiguration/
COPY WebApi/ WebApi/

# Build and publish
RUN dotnet publish WebApi/WebApi.csproj -c Release -o /app/publish --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# Create non-root user for security
RUN groupadd -r starbase && useradd -r -g starbase starbase

# Copy published app
COPY --from=build /app/publish .

# Set ownership
RUN chown -R starbase:starbase /app

# Switch to non-root user
USER starbase

# Expose port (default ASP.NET Core port)
EXPOSE 8080

# Set environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

# Entry point
ENTRYPOINT ["dotnet", "WebApi.dll"]