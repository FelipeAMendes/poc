using BuildingBlocks.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MyResume.Auth.Dtos;
using MyResume.Auth.Models;
using MyResume.Auth.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Poc.Auth.Controllers;

[ApiController]
[Route("[controller]")]
[AllowAnonymous]
public class AccountController : Controller
{
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _configuration;
    private readonly UserManager<UserModel> _userManager;
    private readonly SignInManager<UserModel> _signInManager;

    public AccountController(
        ITokenService tokenService,
        IConfiguration configuration,
        UserManager<UserModel> userManager,
        SignInManager<UserModel> signInManager)
    {
        _tokenService = tokenService;
        _configuration = configuration;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("[action]")]
    public async Task<IActionResult> Login(LoginDto loginDto)
    {
        var user = await _userManager.Users
            .SingleOrDefaultAsync(u => u.Email == loginDto.Email);

        if (user is null)
            return Unauthorized("Usuário ou senha inválidos");

        var result = await _signInManager.CheckPasswordSignInAsync(user, loginDto.Password, lockoutOnFailure: false);
        if (result.Succeeded)
        {
            var tokenResponse = await _tokenService.CreateTokenAsync(user);

            return Ok(tokenResponse);
        }
        if (result.IsLockedOut)
            return Unauthorized("Usuário bloqueado, tente novamente mais tarde");
        else
            return Unauthorized();
    }

    [HttpPost("[action]")]
    public async Task<IActionResult> Register(RegisterDto registerDto)
    {
        var user = new UserModel
        {
            UserName = registerDto.Email,
            Email = registerDto.Email,
            PrivateProfile = false
        };

        var result = await _userManager.CreateAsync(user, registerDto.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        var role = registerDto.IsDefaultUser ? RoleNames.DefaultUser : RoleNames.Company;
        var roleResult = await _userManager.AddToRoleAsync(user, role.ToString());
        if (!roleResult.Succeeded)
            return BadRequest(roleResult.Errors);

        var tokenRsponse = await _tokenService.CreateTokenAsync(user);

        return Ok(tokenRsponse);
    }

    [HttpPost("[action]")]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenDto refreshRequest)
    {
        var principal = GetPrincipalFromRefreshToken(refreshRequest.RefreshToken);
        if (principal is null)
            return Unauthorized(); //Invalid refresh token

        var userId = principal.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
        if (await _userManager.FindByIdAsync(userId) is not { } user)
            return Unauthorized();

        var tokenResult = await _tokenService.CreateTokenAsync(user);

        return Ok(tokenResult);
    }

    private ClaimsPrincipal GetPrincipalFromRefreshToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["Auth:RefreshTokenKey"]!)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true // Validate expiration
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out _);
            return principal;
        }
        catch
        {
            return null; // invalid token
        }
    }
}
