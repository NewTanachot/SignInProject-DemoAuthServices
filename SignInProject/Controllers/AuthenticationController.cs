using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SignInProject.Models;
using SignInProject.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace SignInProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
        }


        [HttpPost]
        [Route("RegisterSignIn")]
        public async Task<IActionResult> RegisterAsync([FromBody] SignInModel model)
        {
            // Check User Duplicate
            var userExists = await userManager.FindByNameAsync(model.Email);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "User already exists!" });
            }

            // Create the User
            var user = new IdentityUser
            {
                Email = model.Email,
                UserName = model.Email,
            };

            var result = await userManager.CreateAsync(user, model.Password);

            // Create Claims
            var claimFirstName = new Claim("FirstName", model.FirstName);
            var claimLastName = new Claim("LastName", model.LastName);
            var claimAge = new Claim("Age", model.age);

            if (result.Succeeded)
            {
                // Add Claims to User
                await userManager.AddClaimAsync(user, claimFirstName);
                await userManager.AddClaimAsync(user, claimLastName);
                await userManager.AddClaimAsync(user, claimAge);

                return Ok(new Response { Status = "Success", Message = "User created successfully!" });
            }

            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Check your password" });
        }


        [HttpPost]
        [Route("LogIn")]
        public async Task<IActionResult> LoginAsync(LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.Email);

            if (user != null)
            {
                // Log in Check
                var LogIncheck = await userManager.CheckPasswordAsync(user, model.Password);

                if (LogIncheck)
                {
                    // Create Access Token from TokenService
                    var TokenService = new TokenServices(configuration, userManager, roleManager, Response);
                    var JwtToken = await TokenService.CreateAccessTokenAsync(user);
                    var AccessToken = new JwtSecurityTokenHandler().WriteToken(JwtToken);

                    // Create and Store Refresh Token from TokenService
                    var Refreshtoken = TokenService.CreateRefreshToken();
                    TokenService.StoreRefreshToken(Refreshtoken);

                    var resultToken = new TokenModel
                    {
                        AccessToken = AccessToken,
                        AccessToken_CreateDate = JwtToken.ValidFrom.ToLocalTime(),
                        AccessToken_ExpireDate = JwtToken.ValidTo.ToLocalTime(),
                        RefreshToken = Refreshtoken.RefreshToken,
                        RefreshToken_CreateDate = Refreshtoken.CreateDate,
                        RefreshToken_ExpireDate = Refreshtoken.ExpireDate
                    };

                    return Ok(resultToken);
                }

                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "Login Fail : Wrong password . . . " });
            }

            return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "Login Fail : Have no accout . . ." });
        }


        [HttpPost]
        [Route("LogOut")]
        public IActionResult LogoutAsync()
        {
            return Ok(new Response { Status = "Success", Message = "Logout successfully!" });
        }

        [HttpPost]
        [Route("RefreshToken")]
        public IActionResult RefreshToken(TokenModel token)
        {
            var refreshTokenCookie = Request.Cookies["RefreshToken"];

            if (token.RefreshToken_ExpireDate >= DateTime.Now)
            {
                if (refreshTokenCookie == token.RefreshToken)
                {
                    //Create New Access Token
                    var TokenService = new TokenServices(configuration, userManager, roleManager, Response);
                    var allClaim = TokenService.GetClaimsFromExpiredToken(token.AccessToken);

                    if (allClaim != null)
                    {
                        var JwtToken = TokenService.CreateAccessToken(allClaim);

                        var AccessToken = new JwtSecurityTokenHandler().WriteToken(JwtToken);

                        var resultToken = new TokenModel
                        {
                            AccessToken = AccessToken,
                            AccessToken_CreateDate = JwtToken.ValidFrom.ToLocalTime(),
                            AccessToken_ExpireDate = JwtToken.ValidTo.ToLocalTime(),
                            RefreshToken = token.RefreshToken,
                            RefreshToken_CreateDate = token.RefreshToken_CreateDate,
                            RefreshToken_ExpireDate = token.RefreshToken_ExpireDate
                        };

                        return Ok(resultToken);
                    }

                    return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "Refresh Fail : Invalid access token . . ." });
                }

                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "Refresh Fail : Invalid refresh token . . ." });
            }

            return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "Refresh Fail : Refresh token expired . . ." });
        }
    }
}
