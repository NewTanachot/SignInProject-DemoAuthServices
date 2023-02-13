using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SignInProject.Models;
using SignInProject.Services;

namespace SignInProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleManagementController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;

        public RoleManagementController (UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
        }

        [Route("GetRole")]
        [HttpGet]
        public List<IdentityRole> GetAllRole()
        {
            // Use Services
            var roleService = new RoleServices(userManager, roleManager);
            return roleService.GetAllRole(); 
        }

        [Route("GetUserByRoleAsync")]
        [HttpGet]
        public async Task<IActionResult> GetUserByRoleAsync(string role)
        {
            if (await roleManager.RoleExistsAsync(role))
            {
                var User = await userManager.GetUsersInRoleAsync(role);
                if (User != null && User.Any())
                {
                    return Ok(User);
                }

                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Get Fail : This role doesn't have any user . . . " });
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Get Fail : Role doesn't exist . . . " });
        }

        [Route("GetRoleByUserAsync")]
        [HttpGet]
        public async Task<IActionResult> GetRoleByUserAsync(string Email)
        {
            var user = await userManager.FindByNameAsync(Email);

            if (user != null)
            {
                var Role = await userManager.GetRolesAsync(user);
                return Ok(Role);
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Get Fail : This user doesn't have any role . . . " });
        }

        [Route("CreateRoleAsync")]
        [HttpPost]
        public async Task<IActionResult> CreateRoleAsync(string role)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
                return Ok(new Response { Status = "Success", Message = $"Create Role {role} Succeeded" });
            }

            return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "Create Fail : Role Already exist . . . " });
        }

        [Route("AssignRoleAsync")]
        [HttpPost]
        public async Task<IActionResult> AssignRoleAsync(EmailOnlyModel model, string role)
        {
            var Role = await roleManager.FindByNameAsync(role);
            var user = await userManager.FindByNameAsync(model.Email);

            if (Role == null )
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Assign Fail : Role doesn't exist . . . " });
            }

            if (user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Assign Fail : User doesn't exist . . . " });
            }

            await userManager.AddToRoleAsync(user, role);
            return Ok(new Response { Status = "Success", Message = $"Add Role {role} to {user.Email}" });
        }

        [Route("RemoveUserAsync")]
        [HttpPut]
        public async Task<IActionResult> RemoveUserAsync(EmailOnlyModel model, string role)
        {
            var Role = await roleManager.FindByNameAsync(role);
            var user = await userManager.FindByNameAsync(model.Email);

            if (Role == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Assign Fail : Role doesn't exist . . . " });
            }

            if (user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Assign Fail : User doesn't exist . . . " });
            }

            var CheckUser = await userManager.GetUsersInRoleAsync(role);

            if (CheckUser.Contains(user))
            {
                await userManager.RemoveFromRoleAsync(user, role);
                return Ok(new Response { Status = "Success", Message = $"Remove Role {role} from {user.Email}" });
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Assign Fail : Role doesn't have this user . . . " });
        }

        [Route("DeleteRoleAsync")]
        [HttpDelete]
        public async Task<IActionResult> DeleteRoleAsync(string role)
        {
            if (await roleManager.RoleExistsAsync(role))
            {
                var Role = await roleManager.FindByNameAsync(role);
                await roleManager.DeleteAsync(Role);
                return Ok(new Response { Status = "Success", Message = $"Delete Role {role} Succeeded" });
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Assign Fail : Role doesn't exist . . . " });
        }
    }
}
