using Humanizer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityAspNetCore.Models;

public class ApplicationUser : IdentityUser
{
    [Required]
    public string? Name { get; set; }
    public DateTime DateCreated{ get; set; }

    [NotMapped]
    [ValidateNever]
    public string Role { get; set; }
    [NotMapped]
    [ValidateNever]
    public string Claim { get; set; }
}
