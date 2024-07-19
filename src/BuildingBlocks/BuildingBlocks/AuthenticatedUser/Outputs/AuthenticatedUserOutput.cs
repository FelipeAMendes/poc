namespace BuildingBlocks.AuthenticatedUser.Outputs;

public class AuthenticatedUserOutput(Guid id, string username, string email)
{
    public Guid Id { get; private set; } = id;
    public string Username { get; private set; } = username;
    public string Email { get; private set; } = email;
}
