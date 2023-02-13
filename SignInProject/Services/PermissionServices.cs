using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace SignInProject.Services
{
    public class PermissionServices
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;

        public PermissionServices(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
        }

        public async Task<IList<Claim>?> GetPermissionByRoleAsync(string role)
        {
            var Role = await roleManager.FindByNameAsync(role);
            var Permission = await roleManager.GetClaimsAsync(Role);

            if (Role != null)
            {
                return Permission;
            }

            return null;
        }
    }
}
