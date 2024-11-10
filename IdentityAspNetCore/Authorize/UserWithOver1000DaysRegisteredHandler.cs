using IdentityAspNetCore.Services;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace IdentityAspNetCore.Authorize;

public class UserWithOver1000DaysRegisteredHandler : AuthorizationHandler<UserWithOver1000DaysRegisteredRequirement>
{
    private readonly IUserOver1000 _userOver1000;
    public UserWithOver1000DaysRegisteredHandler(IUserOver1000 userOver1000)
    {
        _userOver1000 = userOver1000;
    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, UserWithOver1000DaysRegisteredRequirement requirement)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier);

        if (userId == null)
        {
            return Task.CompletedTask;
        }

        var numberOfDays = _userOver1000.GetDays(userId.Value);

        if (numberOfDays >= requirement.Days)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
