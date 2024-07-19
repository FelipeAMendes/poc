namespace MyResume.Auth.Dtos;

public class TokenResponseDto
{
    public TokenResponseDto(string accessToken, string refreshToken, DateTime expiration)
    {
        AccessToken = accessToken;
        RefreshToken = refreshToken;
        Expiration = expiration;
    }

    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime Expiration { get; set; }
}
