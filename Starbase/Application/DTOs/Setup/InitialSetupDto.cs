using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Setup;

/// <summary>
/// Request DTO for initial system setup - creates the first admin user.
/// </summary>
public class InitialSetupDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email must not exceed 256 characters")]
    public required string Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [StringLength(128, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 128 characters")]
    public required string Password { get; set; }

    [Required(ErrorMessage = "First name is required")]
    [StringLength(100, ErrorMessage = "First name must not exceed 100 characters")]
    public required string FirstName { get; set; }

    [Required(ErrorMessage = "Last name is required")]
    [StringLength(100, ErrorMessage = "Last name must not exceed 100 characters")]
    public required string LastName { get; set; }
}