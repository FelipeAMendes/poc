using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using MyResume.Auth.Dtos;
using MyResume.Auth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MyResume.Auth.Services;

public class TokenService(IConfiguration configuration, UserManager<UserModel> userManager, IDataProtectionProvider dataProtectionProvider) : ITokenService
{
    private readonly SymmetricSecurityKey _key = new(Encoding.UTF8.GetBytes(configuration["Auth:TokenKey"]));
    private readonly UserManager<UserModel> _userManager = userManager;
    private readonly IDataProtector _dataProtector = dataProtectionProvider.CreateProtector("RefreshTokenProtector");

    public async Task<TokenResponseDto> CreateTokenAsync(UserModel user)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, user.UserName!),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new("PrivateProfile", user.PrivateProfile.ToString())
        };

        var roles = await _userManager.GetRolesAsync(user);

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var credentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

        var expiration = DateTime.UtcNow.AddMinutes(30);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiration,
            SigningCredentials = credentials,
            Issuer = configuration["Auth:Issuer"]!,
            Audience = configuration["Auth:Audience"]!
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        var securityToken = tokenHandler.CreateToken(tokenDescriptor);

        var token = tokenHandler.WriteToken(securityToken);
        var refreshToken = GenerateRefreshToken(user);

        return new TokenResponseDto(token, refreshToken, expiration);
    }

    private string GenerateRefreshToken(UserModel user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(configuration["Auth:RefreshTokenKey"]!);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new (ClaimTypes.NameIdentifier, user.Id.ToString())
            }),
            Expires = DateTime.UtcNow.AddHours(12),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            Issuer = configuration["Auth:Issuer"]!,
            Audience = configuration["Auth:Audience"]!
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public bool ValidateRefreshToken(string refreshToken)
    {
        try
        {
            var protectedData = Convert.FromBase64String(refreshToken);
            var unprotectedData = _dataProtector.Unprotect(protectedData);
            return true; // outras validações conforme necessário
        }
        catch
        {
            return false;
        }
    }
}
