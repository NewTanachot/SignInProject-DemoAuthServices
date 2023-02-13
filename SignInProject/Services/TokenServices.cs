using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using SignInProject.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SignInProject.Services
{
    public class TokenServices
    {
        private readonly IConfiguration configuration;
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly HttpResponse response;

        public TokenServices(IConfiguration configuration, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, HttpResponse response)
        {
            this.configuration = configuration;
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.response = response;
        }

        public async Task<JwtSecurityToken> CreateAccessTokenAsync(IdentityUser user)
        {
            IEnumerable<Claim> TokenClaims = new List<Claim>();

            // Get UserClaims and UserRoles
            var userClaims = await userManager.GetClaimsAsync(user);
            var userRoles = await userManager.GetRolesAsync(user);

            // Get RoleClaims
            foreach (var roleName in userRoles)
            {
                var Role = await roleManager.FindByNameAsync(roleName);
                var RoleClaim = await roleManager.GetClaimsAsync(Role);

                // Generate Token
                var ClaimRole = new List<Claim> { new Claim(ClaimTypes.Role, roleName) };
                TokenClaims = TokenClaims.Union(ClaimRole).Union(RoleClaim);
            }

            TokenClaims = TokenClaims.Union(userClaims);
            TokenClaims = TokenClaims.DistinctBy(x => (x.Value, x.Type));

            var secretKey = Encoding.UTF8.GetBytes(configuration.GetValue<string>("SecretKey"));

            var jwt = new JwtSecurityToken(
                claims: TokenClaims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256)
            );

            return jwt;
        }

        // CreateAccessTokenAsync Overload !!!
        public JwtSecurityToken CreateAccessToken(List<Claim> allClaims)
        {
            var secretKey = Encoding.UTF8.GetBytes(configuration.GetValue<string>("SecretKey"));

            var jwt = new JwtSecurityToken(
                claims: allClaims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256)
            );

            return jwt;
        }


        public RefreshTokenModel CreateRefreshToken()
        {
            var refreshToken = new RefreshTokenModel
            {
                RefreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                CreateDate = DateTime.Now,
                ExpireDate = DateTime.Now.AddDays(7)
            };

            return refreshToken;
        }

        public void StoreRefreshToken(RefreshTokenModel refreshToken)
        {
            // Store Token in Cookie
            var cookieOption = new CookieOptions
            {
                HttpOnly = true,
                Expires = refreshToken.ExpireDate
            };

            response.Cookies.Append("RefreshToken", refreshToken.RefreshToken, cookieOption);
        }

        public List<Claim> GetClaimsFromExpiredToken(string? token)
        {
            ClaimsPrincipal principal;

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("SecretKey"))),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }

            return principal.Claims.ToList();
        }
    }
}

