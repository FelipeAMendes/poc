using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace MyResume.Web.Models.Auth.Register;

public class RegisterViewModel
{
    [DisplayName("E-mail")]
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [DisplayName("Senha")]
    [Required]
    [StringLength(20, MinimumLength = 6)]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [DisplayName("Confirmação de Senha")]
    [Compare(nameof(Password))]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; }

    [Required]
    public bool IsDefaultUser { get; set; } = true;
}
