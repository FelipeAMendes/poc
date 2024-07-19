using MyResume.Auth.Dtos;
using MyResume.Auth.Models;

namespace MyResume.Auth.Services;

public interface ITokenService
{
    Task<TokenResponseDto> CreateTokenAsync(UserModel user);
    bool ValidateRefreshToken(string refreshToken);
}
