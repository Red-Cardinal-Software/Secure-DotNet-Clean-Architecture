using Application.Common.Exceptions;
using Application.Interfaces.Persistence;

namespace Application.Common.Services;

/// Represents a base application service that provides common functionality for working
/// with a unit of work and facilitates executing operations with automatic commit handling.
public abstract class BaseAppService(IUnitOfWork unitOfWork)
{
    /// Executes the provided asynchronous function and commits the unit of work upon successful execution.
    /// <param name="func">The asynchronous function to execute.</param>
    /// <typeparam name="T">The type of the result returned by the asynchronous function.</typeparam>
    /// <returns>The result of the asynchronous function of type T.</returns>
    protected async Task<T> RunWithCommitAsync<T>(Func<Task<T>> func)
    {
        var result = await func();
        await unitOfWork.CommitAsync();
        return result;
    }

    /// Executes the provided asynchronous function and commits the unit of work upon successful execution.
    /// If a concurrency conflict occurs during commit, returns the fallback result instead of throwing.
    /// <param name="func">The asynchronous function to execute.</param>
    /// <param name="onConcurrencyConflict">Fallback function called when a concurrency conflict is detected.</param>
    /// <typeparam name="T">The type of the result returned by the asynchronous function.</typeparam>
    /// <returns>The result of the asynchronous function, or the fallback result on concurrency conflict.</returns>
    protected async Task<T> RunWithCommitAsync<T>(Func<Task<T>> func, Func<T> onConcurrencyConflict)
    {
        var result = await func();
        try
        {
            await unitOfWork.CommitAsync();
            return result;
        }
        catch (ConcurrencyException)
        {
            return onConcurrencyConflict();
        }
    }

    /// Executes the provided asynchronous function and commits the unit of work upon successful execution.
    /// <param name="func">The asynchronous function to execute.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    protected async Task RunWithCommitAsync(Func<Task> func)
    {
        await func();
        await unitOfWork.CommitAsync();
    }
}
