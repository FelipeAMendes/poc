using IdentityModel.Client;

namespace Poc.Web.HttpHandlers;

public class AuthenticationDelegatingHandler(IHttpContextAccessor httpContextAccessor) : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var user = _httpContextAccessor.HttpContext?.User;
        var accessToken = user?.FindFirst("JWT")?.Value;

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            request.SetBearerToken(accessToken);
        }

        return await base.SendAsync(request, ct);
    }
}
