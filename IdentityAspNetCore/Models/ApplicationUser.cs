using Microsoft.AspNetCore.Identity;

namespace IdentityAspNetCore.Models;

public class ApplicationUser : IdentityUser
{
    public string? Name { get; set; }
}
