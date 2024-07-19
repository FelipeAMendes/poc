using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace MyResume.Web.Models.Auth.Login;

public class LoginViewModel
{
    [DisplayName("E-mail")]
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [DisplayName("Senha")]
    [Required]
    [MinLength(4)]
    [DataType(DataType.Password)]
    public string Password { get; set; }
}
