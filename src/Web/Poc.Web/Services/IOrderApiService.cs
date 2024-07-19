using Refit;

namespace Poc.Web.Services;

public interface IOrderApiService
{
    [Post("/payment-service/order")]
    Task<IApiResponse> CreateOrderAsync();
}
