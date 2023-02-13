using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApp.Data
{
    public class UserDataDbContext : IdentityDbContext
    {
        public UserDataDbContext(DbContextOptions<UserDataDbContext> options) : base(options)
        {

        }
    }
}

