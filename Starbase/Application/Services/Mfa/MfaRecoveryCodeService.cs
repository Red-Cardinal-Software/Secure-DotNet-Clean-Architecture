using Application.Interfaces.Security;
using Domain.Entities.Security;

namespace Application.Services.Mfa;

/// <summary>
/// Service for secure handling of MFA recovery codes with proper password hashing.
/// </summary>
public class MfaRecoveryCodeService(IPasswordHasher passwordHasher)
{
    private readonly IPasswordHasher _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));

    /// <summary>
    /// Generates a new recovery code with secure hashing.
    /// </summary>
    /// <param name="mfaMethodId">The ID of the MFA method</param>
    /// <returns>A new recovery code with secure hash</returns>
    public MfaRecoveryCode GenerateRecoveryCode(Guid mfaMethodId)
    {
        var plainCode = MfaRecoveryCode.GenerateSecureCode();
        var normalizedCode = MfaRecoveryCode.NormalizeCode(plainCode);

        // Use secure password hashing (BCrypt with work factor) instead of fast SHA256
        var hashedCode = _passwordHasher.Hash(normalizedCode);

        return MfaRecoveryCode.Create(mfaMethodId, hashedCode, plainCode);
    }

    /// <summary>
    /// Validates a recovery code against a stored hash using secure verification.
    /// </summary>
    /// <param name="recoveryCode">The recovery code entity to validate against</param>
    /// <param name="inputCode">The plain text code to validate</param>
    /// <returns>True if the code is valid and successfully marked as used</returns>
    public bool ValidateAndUseRecoveryCode(MfaRecoveryCode recoveryCode, string inputCode)
    {
        if (recoveryCode is null || string.IsNullOrWhiteSpace(inputCode))
            return false;

        if (recoveryCode.IsUsed)
            return false;

        var normalizedInput = MfaRecoveryCode.NormalizeCode(inputCode);

        // Use secure password verification with proper work factor
        var isValid = _passwordHasher.Verify(normalizedInput, recoveryCode.HashedCode);

        if (isValid)
        {
            // Mark as used only if validation succeeds
            return recoveryCode.TryMarkAsUsed();
        }

        return false;
    }

    /// <summary>
    /// Generates multiple recovery codes for an MFA method.
    /// </summary>
    /// <param name="mfaMethodId">The ID of the MFA method</param>
    /// <param name="count">Number of recovery codes to generate (default: 10)</param>
    /// <returns>Collection of recovery codes with secure hashes</returns>
    public IEnumerable<MfaRecoveryCode> GenerateRecoveryCodes(Guid mfaMethodId, int count = 10)
    {
        if (count is <= 0 or > 20)
            throw new ArgumentException("Recovery code count must be between 1 and 20", nameof(count));

        var codes = new List<MfaRecoveryCode>(count);

        for (var i = 0; i < count; i++)
        {
            codes.Add(GenerateRecoveryCode(mfaMethodId));
        }

        return codes;
    }
}
