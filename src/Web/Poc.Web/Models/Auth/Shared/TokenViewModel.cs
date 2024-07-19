namespace MyResume.Web.Models.Auth.Shared;

public class TokenViewModel(string accessToken, DateTime expiration)
{
    public string AccessToken { get; set; } = accessToken;
    public DateTime Expiration { get; set; } = expiration;
}
