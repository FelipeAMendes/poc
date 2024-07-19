using MyResume.Web.Models.Auth.Login;
using MyResume.Web.Models.Auth.Register;
using MyResume.Web.Models.Auth.Shared;
using Refit;

namespace Poc.Web.Services;

public interface IAuthApiService
{
    [Post("/auth-service/account/login")]
    Task<IApiResponse<TokenViewModel>> LoginAsync([Body] LoginViewModel loginViewModel, CancellationToken ct);

    [Post("/auth-service/account/register")]
    Task<IApiResponse<TokenViewModel>> RegisterAsync([Body] RegisterViewModel registerViewModel, CancellationToken ct);
}
