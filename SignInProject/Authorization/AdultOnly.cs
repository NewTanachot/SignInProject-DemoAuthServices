using Microsoft.AspNetCore.Authorization;

namespace SignInProject.Authorization
{
    public class AdultOnly : IAuthorizationRequirement
    {
        public int age { get; }

        public AdultOnly(int age)
        {
            this.age = age;
        } 
    }

    public class AdultOnlyHandler : AuthorizationHandler<AdultOnly>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdultOnly requirement)
        {
            var UserAge = int.Parse(context.User.FindFirst(x => x.Type == "Age").Value);

            if (UserAge > requirement.age)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
