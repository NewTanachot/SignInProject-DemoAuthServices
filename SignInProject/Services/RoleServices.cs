using Microsoft.AspNetCore.Identity;

namespace SignInProject.Services
{
    public class RoleServices
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;

        public RoleServices (UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
        }

        public List<IdentityRole> GetAllRole()
        {
            var allRole = roleManager.Roles.ToList();
            return allRole;
        }
    }
}
