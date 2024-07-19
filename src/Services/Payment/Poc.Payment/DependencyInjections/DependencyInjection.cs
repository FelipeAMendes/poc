using BuildingBlocks.AuthenticatedUser;
using BuildingBlocks.AuthenticatedUser.Interfaces;
using BuildingBlocks.Extensions;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MyResume.Payment.DependencyInjections;

public static class DependencyInjection
{
    public static IServiceCollection AddApiServices(this IServiceCollection services, IConfiguration configuration)
    {
        AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);
        AppContext.SetSwitch("Npgsql.DisableDateTimeInfinityConversions", true);

        services.AddControllers()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
                    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
                });

        services.AddDefaultAuthentication(configuration);

        services.AddAuthorization(opt =>
                {
                    opt.AddPolicy("IsDefaultUser", policy => policy.RequireRole("DefaultUser"));
                    opt.AddPolicy("IsAdmin", policy => policy.RequireRole("Admin"));
                });

        services.AddHttpContextAccessor();
        services.AddScoped<IAuthenticatedUser, AuthenticatedUser>();

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options => options.CustomSchemaIds(type => type.ToString()));

        return services;
    }

    public static WebApplication UseApiServices(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        else
        {
            app.UseHttpsRedirection();
        }

        app.UseExceptionHandler(options => { });

        app.UseAuthentication();

        app.UseRouting();

        app.UseAuthorization();

        app.MapControllers();

        return app;
    }
}
