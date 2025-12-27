using Application.Models;

namespace Application.Common.Factories;

public static class ServiceResponseFactory
{
    public static ServiceResponse<T> Success<T>(T data, string? message = null) =>
        new() { Data = data, Success = true, Message = message ?? "" };

    public static ServiceResponse<T> Success<T>(string message) =>
        new() { Success = true, Message = message };

    public static ServiceResponse<T> Error<T>(string message, int status = 400) =>
        new() { Data = default, Success = false, Message = message, Status = status };

    public static ServiceResponse<T> Error<T>(string message, T data, int status = 400) =>
        new() { Data = data, Success = false, Message = message, Status = status };

    public static ServiceResponse<T> NotFound<T>(string message) =>
        new() { Data = default, Success = false, Message = message, Status = 404 };
}