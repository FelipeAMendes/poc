using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MyResume.Auth.Data;
using MyResume.Auth.Models;
using MyResume.Auth.Services;

namespace MyResume.Auth.DependencyInjections;

public static class DependencyInjection
{
    public static void AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddNpgsqlDataSource(configuration["ConnectionStrings:Auth"]);
        services.AddDbContext<ApplicationDbContext>((sp, options) => options.UseNpgsql(configuration["ConnectionStrings:Auth"]));
        services.AddDatabaseDeveloperPageExceptionFilter();

        services.AddIdentity<UserModel, IdentityRole>(options =>
                {
                    options.User.RequireUniqueEmail = true;
                    options.SignIn.RequireConfirmedAccount = false;
                    options.Password.RequireDigit = true;
                    options.Password.RequireLowercase = true;
                    options.Password.RequireUppercase = true;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequiredLength = 6;
                })
                .AddRoles<IdentityRole>()
                .AddRoleManager<RoleManager<IdentityRole>>()
                .AddSignInManager<SignInManager<UserModel>>()
                .AddRoleValidator<RoleValidator<IdentityRole>>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

        services.AddDataProtection();

        services.AddTransient<ITokenService, TokenService>();

        MigrateDatabase(services);
    }

    private static void MigrateDatabase(IServiceCollection services)
    {
        var sp = services.BuildServiceProvider();
        var context = sp.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate();
    }
}
