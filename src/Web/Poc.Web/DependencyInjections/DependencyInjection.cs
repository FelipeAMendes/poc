using BuildingBlocks.AuthenticatedUser;
using BuildingBlocks.AuthenticatedUser.Interfaces;
using Microsoft.AspNetCore.Authentication.Cookies;
using Poc.Web.HttpHandlers;
using Poc.Web.Services;
using Refit;

namespace Poc.Web.DependencyInjections;

public static class DependencyInjection
{
    public static void AddApiServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddTransient<AuthenticationDelegatingHandler>();
        services.AddHttpContextAccessor();
        services.AddRefitClient<IAdminApiService>()
                .ConfigureHttpClient(c =>
                {
                    c.BaseAddress = new Uri(configuration["ApiSettings:GatewayUrl"]!);
                    c.Timeout = TimeSpan.FromSeconds(59);
                })
                .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddRefitClient<IOrderApiService>()
                .ConfigureHttpClient(c =>
                {
                    c.BaseAddress = new Uri(configuration["ApiSettings:GatewayUrl"]!);
                    c.Timeout = TimeSpan.FromSeconds(59);
                })
                .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddRefitClient<ICatalogApiService>()
                .ConfigureHttpClient(c =>
                {
                    c.BaseAddress = new Uri(configuration["ApiSettings:GatewayUrl"]!);
                    c.Timeout = TimeSpan.FromSeconds(59);
                });

        services.AddRefitClient<IAuthApiService>()
                .ConfigureHttpClient(c =>
                {
                    c.BaseAddress = new Uri(configuration["ApiSettings:GatewayUrl"]!);
                    c.Timeout = TimeSpan.FromSeconds(59);
                });
    }

    public static void AddCustomAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.LoginPath = new PathString("/Login");
                    options.AccessDeniedPath = new PathString("/Denied");
                    //options.ExpireTimeSpan = TimeSpan.FromHours(24);

                    options.Cookie.SameSite = SameSiteMode.Strict; // Melhor segurança
                    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // CookieSecurePolicy.Always - HTTPS
                    options.Cookie.IsEssential = true;
                });

        services.AddScoped<IAuthenticatedUser, AuthenticatedUser>();
    }

    private static readonly string[] SupportedCultures = ["pt-BR"];

    public static void AddCustomLocalization(this IServiceCollection services)
    {
        services.Configure<RequestLocalizationOptions>(options =>
        {
            options.SetDefaultCulture(SupportedCultures[0])
                   .AddSupportedCultures(SupportedCultures)
                   .AddSupportedUICultures(SupportedCultures);
        });
    }

    public static void AddCsrfValidation(this IServiceCollection services)
    {
        services.AddAntiforgery(options =>
        {
            // Set Cookie properties using CookieBuilder properties†.
            options.FormFieldName = "AntiforgeryFieldname";
            options.HeaderName = "X-CSRF-TOKEN-HEADERNAME";
            options.SuppressXFrameOptionsHeader = false;
        });
    }
}
