using Poc.Web.DependencyInjections;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews()
                .AddMvcLocalization();
builder.Services.AddApiServices(builder.Configuration);
builder.Services.AddCustomAuthentication();
builder.Services.AddCustomLocalization();
builder.Services.AddCsrfValidation();

var app = builder.Build();

if (builder.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseAntiforgery();

app.UseStaticFiles();

app.UseAuthentication();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
