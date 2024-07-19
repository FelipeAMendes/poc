using BuildingBlocks.AuthenticatedUser.Outputs;

namespace BuildingBlocks.AuthenticatedUser.Interfaces;

public interface IAuthenticatedUser
{
    AuthenticatedUserOutput GetDataFromUser();
    bool IsAuthenticated();
    string GetAccessToken();
    List<string> GetRoles();
}
