using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace SignInProject.Controllers
{
    [Authorize(Policy = "AuthorizeAll", Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class ViewProfileController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;

        public ViewProfileController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet] 
        public async Task<IActionResult>GetInfoAsync(string Email)
        {
            
            var user = await _userManager.FindByEmailAsync(Email);

            // For getInfo in claims
            var claims = await _userManager.GetClaimsAsync(user);
            var FirstNameClaim = claims.FirstOrDefault(x => x.Type == "FirstName");
            var LastNameClaim = claims.FirstOrDefault(x => x.Type == "LastName");
            var AgeClaim = claims.FirstOrDefault(x => x.Type == "Age");

            // Return multi type by Anonymous object
            return Ok( new { user.UserName, user.Email, FirstName =  FirstNameClaim.Value, Lastname = LastNameClaim.Value , Age = AgeClaim.Value} );
        }
    }
}
