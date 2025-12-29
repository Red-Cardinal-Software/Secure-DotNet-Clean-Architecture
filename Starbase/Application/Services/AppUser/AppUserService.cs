using System.Security.Claims;
using Application.Common.Constants;
using Application.Common.Factories;
using Application.Common.Services;
using Application.Common.Utilities;
using Application.DTOs.Users;
using Application.Interfaces.Mappers;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using Application.Logging;
using Application.Models;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace Application.Services.AppUser;

/// <summary>
/// Provides services related to application users. This includes functionality for
/// administrative tasks such as retrieving users, deactivating users, adding new users,
/// and updating user information, as well as retrieving basic user information.
/// </summary>
public class AppUserService(
    IAppUserRepository appUserRepository,
    IUnitOfWork unitOfWork,
    IAppUserMapper appUserMapper,
    IValidator<string> passwordValidator,
    ILogger<AppUserService> logger
    )
    : BaseAppService(unitOfWork), IAppUserService
{
    public async Task<ServiceResponse<List<AppUserDto>>> AdminGetUsersAsync(ClaimsPrincipal user)
    {
        var users = await appUserRepository.GetUsersForOrganizationAsync(RoleUtility.GetOrgIdFromClaims(user));

        var usersDto = users.Select(appUserMapper.ToDto).ToList();

        SecurityEvent.UserManagement(logger,
            SecurityEvent.Type.Access,
            "user-list",
            SecurityEvent.Outcome.Success,
            $"Retrieved {usersDto.Count} users",
            user);

        return ServiceResponseFactory.Success(usersDto);
    }

    public async Task<ServiceResponse<bool>> AdminDeactivateUserAsync(ClaimsPrincipal user, Guid id) =>
        await RunWithCommitAsync(async () =>
    {
        var userToDeactivate = await appUserRepository.GetUserByIdAsync(id);
        var requestingUserOrg = RoleUtility.GetOrgIdFromClaims(user);

        if (userToDeactivate is null)
        {
            SecurityEvent.UserManagement(logger,
                SecurityEvent.Type.Change,
                "user-deactivate",
                SecurityEvent.Outcome.Failure,
                $"User not found for deactivation: {id}",
                user);
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.UserNotFound);
        }

        if (userToDeactivate.OrganizationId != requestingUserOrg)
        {
            SecurityEvent.Threat(logger, "user-deactivate",
                $"Unauthorized cross-organization user deactivation attempt: {userToDeactivate.Id}",
                reason: "User belongs to different organization",
                user: user);
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.UserUnauthorized);
        }

        userToDeactivate.Deactivate();

        SecurityEvent.UserManagement(logger,
            SecurityEvent.Type.Change,
            "user-deactivate",
            SecurityEvent.Outcome.Success,
            $"User deactivated: {id}",
            user,
            targetUser: userToDeactivate.Username);

        return ServiceResponseFactory.Success(true);
    });

    public async Task<ServiceResponse<AppUserDto>> AdminAddNewUserAsync(ClaimsPrincipal user, CreateNewUserDto newUser) =>
        await RunWithCommitAsync(async () =>
        {
            var validPasswordResult = await passwordValidator.ValidateAsync(newUser.Password);

            if (!validPasswordResult.IsValid)
            {
                SecurityEvent.UserManagement(logger,
                    SecurityEvent.Type.Creation,
                    "user-create",
                    SecurityEvent.Outcome.Failure,
                    "User creation failed: invalid password",
                    user);

                return ServiceResponseFactory.Error<AppUserDto>(string.Join(", ", validPasswordResult.Errors.Select(e => e.ErrorMessage)));
            }

            var requestingOrgId = RoleUtility.GetOrgIdFromClaims(user);
            var newUserEntity = await appUserMapper.MapForCreate(newUser, requestingOrgId);

            var newUserSavedEntity = await appUserRepository.CreateUserAsync(newUserEntity);

            var newUserDto = appUserMapper.ToDto(newUserSavedEntity);

            SecurityEvent.UserManagement(logger,
                SecurityEvent.Type.Creation,
                "user-create",
                SecurityEvent.Outcome.Success,
                $"User created: {newUserSavedEntity.Username}",
                user,
                targetUser: newUserSavedEntity.Username);

            return ServiceResponseFactory.Success(newUserDto);
        });

    public async Task<ServiceResponse<AppUserDto>> UpdateUserAsync(ClaimsPrincipal user, AppUserDto appUserDto) => await RunWithCommitAsync(async () =>
    {
        var requestingOrgId = RoleUtility.GetOrgIdFromClaims(user);
        var userToUpdate = await appUserRepository.GetUserByIdAsync(appUserDto.Id);

        if (userToUpdate is null)
        {
            SecurityEvent.UserManagement(logger,
                SecurityEvent.Type.Change,
                "user-update",
                SecurityEvent.Outcome.Failure,
                $"User not found for update: {appUserDto.Id}",
                user);
            return ServiceResponseFactory.Error<AppUserDto>(ServiceResponseConstants.UserNotFound);
        }

        if (requestingOrgId != userToUpdate.OrganizationId)
        {
            SecurityEvent.Threat(logger, "user-update",
                $"Unauthorized cross-organization user update attempt: {userToUpdate.Id}",
                reason: "User belongs to different organization",
                user: user);
            return ServiceResponseFactory.Error<AppUserDto>(ServiceResponseConstants.UserUnauthorized);
        }

        userToUpdate = await appUserMapper.MapForUpdate(userToUpdate, appUserDto);

        var updatedDto = appUserMapper.ToDto(userToUpdate);

        return ServiceResponseFactory.Success(updatedDto);
    });

    public async Task<ServiceResponse<List<BasicAppUserDto>>> GetBasicUsersAsync(ClaimsPrincipal user)
    {
        var users = await appUserRepository.GetUsersForOrganizationAsync(RoleUtility.GetOrgIdFromClaims(user));
        var basicUsersDto = users.Select(appUserMapper.ToBasicDto).ToList();

        SecurityEvent.UserManagement(logger,
            SecurityEvent.Type.Access,
            "user-list-basic",
            SecurityEvent.Outcome.Success,
            $"Retrieved {basicUsersDto.Count} basic users",
            user);

        return ServiceResponseFactory.Success(basicUsersDto);
    }
}
