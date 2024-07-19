namespace MyResume.Auth.Dtos;

public class ChangePasswordDto
{
    public string NewPassword { get; init; }
    public string OldPassword { get; init; }
}