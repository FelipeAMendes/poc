using Refit;

namespace Poc.Web.Services;

public interface IAdminApiService
{
    [Get("/admin-service/manage")]
    Task<IApiResponse> GetAsync();

    [Post("/admin-service/manage")]
    Task<IApiResponse> CreateAsync();

    [Put("/admin-service/manage")]
    Task<IApiResponse> UpdateAsync();

    [Delete("/admin-service/manage/{request.Id}")]
    Task<IApiResponse> DeleteAsync();
}
