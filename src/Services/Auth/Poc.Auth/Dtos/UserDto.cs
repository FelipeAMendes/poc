namespace MyResume.Auth.Dtos;

public class UserDto
{
    public string Id { get; set; }
    public string UserName { get; set; }
    public bool PrivateProfile { get; set; }
    public string Email { get; set; }
    public bool EmailConfirmed { get; set; }
    public object PhoneNumber { get; set; }
    public bool PhoneNumberConfirmed { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public bool LockoutEnabled { get; set; }
}
