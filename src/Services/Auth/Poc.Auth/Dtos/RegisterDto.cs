using System.ComponentModel.DataAnnotations;

namespace MyResume.Auth.Dtos;

public class RegisterDto
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [StringLength(20, MinimumLength = 6)]
    public string Password { get; set; }
    
    [Compare(nameof(Password))]
    public string ConfirmPassword { get; set; }

    [Required]
    public bool IsDefaultUser { get; set; } = true;
}
