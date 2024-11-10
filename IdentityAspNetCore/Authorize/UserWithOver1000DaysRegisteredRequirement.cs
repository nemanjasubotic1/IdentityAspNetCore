using Microsoft.AspNetCore.Authorization;

namespace IdentityAspNetCore.Authorize;

public class UserWithOver1000DaysRegisteredRequirement : IAuthorizationRequirement
{
    public int Days { get; set; }
    public UserWithOver1000DaysRegisteredRequirement(int days)
    {
        Days = days;    
    }
}
