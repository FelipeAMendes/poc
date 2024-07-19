using Microsoft.AspNetCore.Identity;

namespace MyResume.Auth.Models;

public class UserModel : IdentityUser
{
    public bool PrivateProfile { get; set; }
}
