using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Auth;

public class UserLoginDto
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(256, ErrorMessage = "Username must not exceed 256 characters")]
    [RegularExpression(@"^[^\u0000-\u001F]*$", ErrorMessage = "Username contains invalid characters")]
    public required string Username { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [StringLength(128, ErrorMessage = "Password must not exceed 128 characters")]
    public required string Password { get; set; }
}