using System.IdentityModel.Tokens.Jwt;

namespace SignInProject.Models
{
    public class TokenModel
    {
       public string? AccessToken { get; set; }

       public DateTime AccessToken_CreateDate { get; set; } = DateTime.Now;

       public DateTime AccessToken_ExpireDate { get; set; }

       public string? RefreshToken { get; set; }

       public DateTime RefreshToken_CreateDate { get; set; } = DateTime.Now;

       public DateTime RefreshToken_ExpireDate { get; set; }
    }
}
