using Xunit;
using Moq;
using System.Security.Claims;
using Application.Interfaces.Repositories;
using Application.DTOs.Users;
using Application.Services.AppUser;
using Application.Interfaces.Mappers;
using Application.Common.Utilities;
using Application.Common.Constants;
using Domain.Entities.Identity;
using FluentAssertions;
using Application.Interfaces.Persistence;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.Extensions.Logging;
using TestUtils.EntityBuilders;
using TestUtils.Utilities;

namespace Application.Tests.ServiceTests
{
    public class AppUserServiceTests
    {
        private readonly Mock<IAppUserRepository> _userRepoMock = new();
        private readonly Mock<IUnitOfWork> _unitOfWorkMock = new();
        private readonly Mock<IAppUserMapper> _mapperMock = new();
        private readonly Mock<ILogger<AppUserService>> _loggerMock = new();
        private readonly Mock<IValidator<string>> _passwordValidatorMock = new();
        private readonly ClaimsPrincipal _claimsUser;

        private readonly AppUserService _service;

        public AppUserServiceTests()
        {
            _claimsUser = ClaimsPrincipalFactory.CreateClaim(TestConstants.Ids.OrganizationId, Guid.NewGuid());
            _service = new AppUserService(_userRepoMock.Object, _unitOfWorkMock.Object, _mapperMock.Object, _passwordValidatorMock.Object, _loggerMock.Object);
        }

        [Fact]
        public async Task AdminGetUsersAsync_ShouldReturnUsersForOrganization()
        {
            var users = new List<AppUser> { new AppUserBuilder().Build() };
            _userRepoMock.Setup(r => r.GetUsersForOrganizationAsync(It.IsAny<Guid>())).ReturnsAsync(users);
            _mapperMock.Setup(m => m.ToDto(It.IsAny<AppUser>())).Returns(new AppUserDto());

            var result = await _service.AdminGetUsersAsync(_claimsUser);

            result.Success.Should().BeTrue();
            result.Data.Should().HaveCount(1);
        }

        [Fact]
        public async Task AdminDeactivateUserAsync_ShouldReturnError_WhenUserNotFound()
        {
            _userRepoMock.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>())).ReturnsAsync((AppUser?)null);

            var result = await _service.AdminDeactivateUserAsync(_claimsUser, Guid.NewGuid());

            result.Success.Should().BeFalse();
            result.Message.Should().Be(ServiceResponseConstants.UserNotFound);
        }

        [Fact]
        public async Task AdminDeactivateUserAsync_ShouldReturnError_WhenUnauthorizedOrg()
        {
            var otherOrgId = Guid.NewGuid();
            _userRepoMock.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>()))
                .ReturnsAsync(new AppUserBuilder().WithOrganizationId(otherOrgId).Build());

            var result = await _service.AdminDeactivateUserAsync(_claimsUser, Guid.NewGuid());

            result.Success.Should().BeFalse();
            result.Message.Should().Be(ServiceResponseConstants.UserUnauthorized);
        }

        [Fact]
        public async Task AdminDeactivateUserAsync_ShouldSucceed_WhenUserIsDeactivated()
        {
            var orgId = RoleUtility.GetOrgIdFromClaims(_claimsUser);
            var user = new AppUserBuilder().WithOrganizationId(orgId).Build();
            _userRepoMock.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>())).ReturnsAsync(user);

            var result = await _service.AdminDeactivateUserAsync(_claimsUser, Guid.NewGuid());

            result.Success.Should().BeTrue();
        }

        [Fact]
        public async Task AdminAddNewUserAsync_ShouldAddUserSuccessfully()
        {
            var dto = new CreateNewUserDto
            {
                FirstName = "test",
                LastName = "User",
                Password = "strongnewpassword",
                Roles = [],
                Username = "test"
            };
            var user = new AppUserBuilder().Build();
            _mapperMock.Setup(m => m.MapForCreate(It.IsAny<CreateNewUserDto>(), It.IsAny<Guid>())).ReturnsAsync(user);
            _userRepoMock.Setup(r => r.CreateUserAsync(It.IsAny<AppUser>())).ReturnsAsync(user);
            _mapperMock.Setup(m => m.ToDto(It.IsAny<AppUser>())).Returns(new AppUserDto());
            _passwordValidatorMock.Setup(p => p.ValidateAsync("strongnewpassword", CancellationToken.None)).ReturnsAsync(new ValidationResult());

            var result = await _service.AdminAddNewUserAsync(_claimsUser, dto);

            result.Success.Should().BeTrue();
            result.Data.Should().NotBeNull();
        }

        [Fact]
        public async Task UpdateUserAsync_ShouldReturnError_WhenUserNotFound()
        {
            _userRepoMock.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>())).ReturnsAsync((AppUser?)null);

            var result = await _service.UpdateUserAsync(_claimsUser, new AppUserDto { Id = Guid.NewGuid() });

            result.Success.Should().BeFalse();
            result.Message.Should().Be(ServiceResponseConstants.UserNotFound);
        }

        [Fact]
        public async Task UpdateUserAsync_ShouldReturnError_WhenUnauthorizedOrg()
        {
            var user = new AppUserBuilder().WithOrganizationId(Guid.NewGuid()).Build();
            _userRepoMock.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>())).ReturnsAsync(user);

            var result = await _service.UpdateUserAsync(_claimsUser, new AppUserDto { Id = Guid.NewGuid() });

            result.Success.Should().BeFalse();
            result.Message.Should().Be(ServiceResponseConstants.UserUnauthorized);
        }

        [Fact]
        public async Task UpdateUserAsync_ShouldUpdateUser_WhenValid()
        {
            var orgId = RoleUtility.GetOrgIdFromClaims(_claimsUser);
            var user = new AppUserBuilder().WithOrganizationId(orgId).Build();
            _userRepoMock.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>())).ReturnsAsync(user);
            _mapperMock.Setup(m => m.MapForUpdate(It.IsAny<AppUser>(), It.IsAny<AppUserDto>())).ReturnsAsync(user);
            _mapperMock.Setup(m => m.ToDto(It.IsAny<AppUser>())).Returns(new AppUserDto());

            var result = await _service.UpdateUserAsync(_claimsUser, new AppUserDto { Id = user.Id });

            result.Success.Should().BeTrue();
        }

        [Fact]
        public async Task GetBasicUsersAsync_ShouldReturnBasicUserDtos()
        {
            var users = new List<AppUser> { new AppUserBuilder().Build() };

            var userDto = new BasicAppUserDto
            {
                FirstName = users[0].FirstName,
                LastName = users[0].LastName,
                Username = users[0].Username
            };

            _userRepoMock.Setup(r => r.GetUsersForOrganizationAsync(It.IsAny<Guid>())).ReturnsAsync(users);
            _mapperMock.Setup(m => m.ToBasicDto(It.IsAny<AppUser>())).Returns(userDto);

            var result = await _service.GetBasicUsersAsync(_claimsUser);

            result.Success.Should().BeTrue();
            result.Data.Should().HaveCount(1);
        }
    }
}
