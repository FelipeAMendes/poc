using Refit;

namespace Poc.Web.Services;

public interface ICatalogApiService
{
    [Get("/public-service/catalog/{title}")]
    Task<IApiResponse> GetCatalogAsync(string title);
}
