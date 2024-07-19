using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using MyResume.Auth.Models;

namespace MyResume.Auth.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityDbContext(options)
{
    public DbSet<UserModel> IdentityUser { get; set; }
}

//Migrations
public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
        optionsBuilder.UseNpgsql("Server=pocdb;Port=5432;Database=pocauthdb;User Id=postgres;Password=postgres;Include Error Detail=true");

        return new ApplicationDbContext(optionsBuilder.Options);
    }
}