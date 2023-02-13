using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SignInProject.Models;
using SignInProject.Services;
using System.Security.Claims;

namespace SignInProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PermissionManagementController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly UserManager<IdentityUser> userManager;

        public PermissionManagementController (RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            this.roleManager = roleManager;
            this.userManager = userManager;
        }

        [Route("GetPermissionAsync")]
        [HttpGet]
        public async Task<IActionResult> GetAllPremissionAsync()
        {
            IEnumerable<Claim> allPermission = new List<Claim>();

            // Use roleService
            var roleService = new RoleServices(userManager, roleManager);
            var permissionService = new PermissionServices(userManager, roleManager);

            var allRole = roleService.GetAllRole();
            foreach (var role in allRole)
            {
                var rolePermission = await permissionService.GetPermissionByRoleAsync(role.Name);
                allPermission = allPermission.Union(rolePermission);
            }

            return Ok(allPermission.DistinctBy(x => x.Value));
        }

        [Route("GetPermissionByRoleAsync")]
        [HttpGet]
        public async Task<IActionResult> GetPermissionByRoleAsync(string role)
        {
            // Use roleService
            var permissionService = new PermissionServices(userManager, roleManager);
            var Permission = await permissionService.GetPermissionByRoleAsync(role);

            if(Permission != null)
            {
                return Ok(Permission);
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Get Permission Fail : Role doesn't exist . . . " });
        }

        [Route("GetRoleByPermissionAsync")]
        [HttpGet]
        public async Task<IActionResult> GetRoleByPermissionAsync(string permission)
        {
            List<IdentityRole> allRoleInPermission = new List<IdentityRole>();

            // Use roleService
            var roleService = new RoleServices(userManager, roleManager);
            var allRole = roleService.GetAllRole();
            foreach (var role in allRole)
            {
                var rolePermission = await roleManager.GetClaimsAsync(role);
                foreach (var _rolePermission in rolePermission)
                {
                    if (_rolePermission.Value == permission)
                    {
                        allRoleInPermission.Add(role);
                    }
                }
            }

            if (allRoleInPermission.Any())
            {
                return Ok(allRoleInPermission);
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Get Permission Fail : Permission doesn't exist in any role . . . " });
        }

        [Route("AssignPermissionAsync")]
        [HttpPost]
        public async Task<IActionResult> AddPermissionAsync(string role, string permission)
        {
            var Role = await roleManager.FindByNameAsync(role);
            var RoleClaim = await roleManager.GetClaimsAsync(Role);

            if (Role == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Add Permission Fail : Role doesn't exist . . . " });
            }

            foreach (var roleclaim in RoleClaim)
            {
                if (roleclaim.Value == permission)
                {
                    return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Add Permission Fail : Permission Already exist . . . " });
                }
            }

            var claimPermission = new Claim("Permission", permission);
            await roleManager.AddClaimAsync(Role, claimPermission);
            return Ok(new Response { Status = "Success", Message = "Permission add successfully!" });
        }

        [Route("DeletePermissionAsync")]
        [HttpDelete]
        public async Task<IActionResult> DeletePermissionAsync(string role, string permission)
        {
            var Role = await roleManager.FindByNameAsync(role);
            var RoleClaim = await roleManager.GetClaimsAsync(Role);

            if (Role == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Remove Permission Fail : Role doesn't exist . . . " });
            }

            foreach (var roleclaim in RoleClaim)
            {
                if (roleclaim.Value == permission)
                {
                    await roleManager.RemoveClaimAsync(Role, roleclaim);
                    return Ok(new Response { Status = "Success", Message = "Permission remove successfully!" });
                }
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Add Permission Fail : Permission doesn't exist . . . " });

        }
    }
}
