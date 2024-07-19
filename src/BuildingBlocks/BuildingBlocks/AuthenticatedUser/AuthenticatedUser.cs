using BuildingBlocks.AuthenticatedUser.Interfaces;
using BuildingBlocks.AuthenticatedUser.Outputs;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace BuildingBlocks.AuthenticatedUser;

public class AuthenticatedUser(IHttpContextAccessor accessor) : IAuthenticatedUser
{
    private readonly IHttpContextAccessor _accessor = accessor;

    public AuthenticatedUserOutput GetDataFromUser()
    {
        var userClaims = _accessor.HttpContext.User.Claims;

        var id = userClaims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
        var username = userClaims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
        var email = userClaims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;//JwtRegisteredClaimNames

        Guid.TryParse(id, out var idToken);
        username = username[..username.IndexOf('@')];
        return new AuthenticatedUserOutput(idToken, username, email);
    }

    public bool IsAuthenticated()
    {
        var isAuthenticated = _accessor.HttpContext.User.Identity.IsAuthenticated;

        return isAuthenticated;
    }

    public string GetAccessToken()
    {
        var authorization = _accessor.HttpContext.Request.Headers.Authorization.ToString();
        var accessToken = authorization.Replace("Bearer ", "");

        return accessToken;
    }

    public List<string> GetRoles()
    {
        var roles = _accessor.HttpContext.User.Claims.Where(x => x.Type == ClaimTypes.Role)
                                                     .Select(x => x.Value)
                                                     .ToList();
        return roles;
    }
}