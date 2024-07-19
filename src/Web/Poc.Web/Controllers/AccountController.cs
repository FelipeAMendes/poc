using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyResume.Web.Models.Auth.Login;
using MyResume.Web.Models.Auth.Register;
using Poc.Web.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace Poc.Web.Controllers;

public class AccountController : Controller
{
    private readonly IAuthApiService _service;
    private readonly IConfiguration _configuration;

    public AccountController(IAuthApiService service, IConfiguration configuration)
    {
        _service = service;
        _configuration = configuration;
    }

    [HttpGet("Login")]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost("Login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginAsync([FromForm] LoginViewModel loginViewModel, CancellationToken ct, [FromQuery] string returnUrl = null)
    {
        if (!ModelState.IsValid)
            return View();

        var response = await _service.LoginAsync(loginViewModel, ct);
        if (!response.IsSuccessStatusCode)
        {
            TempData["Error"] = "Usuário ou Senha inválidos";
            return View();
        }

        if (string.IsNullOrEmpty(response.Content!.AccessToken))
        {
            TempData["Error"] = "Usuário ou Senha inválidos";
            return View();
        }

        var signInSuccess = await SignInAsync(response.Content.AccessToken);
        if (!signInSuccess)
        {
            TempData["Error"] = "Usuário ou Senha inválidos";
            return View();
        }

        var decodedUrl = GetReturnUrl(returnUrl ?? "Home/Index");

        if (Url.IsLocalUrl(decodedUrl))
            return Redirect(decodedUrl);

        return RedirectToAction("Index", "Home");
    }

    [HttpGet("Register")]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost("Register")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterAsync([FromForm] RegisterViewModel registerViewModel, CancellationToken ct, [FromQuery] string returnUrl = null)
    {
        if (!ModelState.IsValid)
            return View();

        var response = await _service.RegisterAsync(registerViewModel, ct);
        if (!response.IsSuccessStatusCode)
        {
            TempData["Error"] = "Ocorreu um erro";
            return View();
        }

        if (string.IsNullOrEmpty(response.Content.AccessToken))
        {
            TempData["Error"] = "Usuário ou Senha inválidos";
            return View();
        }

        var signInResult = await SignInAsync(response.Content.AccessToken);
        if (!signInResult)
        {
            TempData["Error"] = "Usuário ou Senha inválidos";
            return View();
        }

        var decodedUrl = GetReturnUrl(returnUrl ?? "Home/Index");

        if (Url.IsLocalUrl(decodedUrl))
            return Redirect(decodedUrl);

        return RedirectToAction("Index", "Home");
    }

    [HttpGet("Logout")]
    public async Task<IActionResult> LogoutAsync(string returnUrl = null)
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        var decodedUrl = GetReturnUrl(returnUrl ?? "Home/Index");

        if (Url.IsLocalUrl(decodedUrl))
            return Redirect(decodedUrl);

        return RedirectToAction("Index", "Home");
    }

    private string GetReturnUrl(string returnUrl)
    {
        string decodedUrl = "";
        if (!string.IsNullOrEmpty(returnUrl))
            decodedUrl = WebUtility.UrlDecode(returnUrl);

        return decodedUrl;
    }

    private async Task<bool> SignInAsync(string token)
    {
        var validToken = ValidateJwtToken(token);
        if (validToken is null || validToken?.Identity is { IsAuthenticated: false })
            return false;

        var jsonToken = new JwtSecurityTokenHandler().ReadToken(token) as JwtSecurityToken;
        var jsonClaims = jsonToken.Claims;

        var id = jsonClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.NameId).Value;
        var username = jsonClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.UniqueName).Value;
        var email = jsonClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email).Value;
        var roles = jsonClaims.Where(c => c.Type == "role").Select(x => new Claim(ClaimTypes.Role, x.Value));

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, id),
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Email, email),
            new("JWT", token) // Adiciona o token JWT como claim
        };
        claims.AddRange(roles);

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            AllowRefresh = true,
            ExpiresUtc = jsonToken.ValidTo.ToUniversalTime(),
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true, // Evita acesso por JavaScript
            Secure = false, // TODO: true (Apenas HTTPS)
            Expires = jsonToken.ValidTo,
            SameSite = SameSiteMode.Strict,
            Path = "/"
        };

        return true;
    }

    private ClaimsPrincipal ValidateJwtToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["Auth:TokenKey"]!);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = _configuration["Auth:Issuer"]!,
            ValidateAudience = true,
            ValidAudience = _configuration["Auth:Audience"]!,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // Sem margem de erro
        };

        try
        {
            var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
            return principal;
        }
        catch
        {
            // Invalid token
            return null;
        }
    }
}

