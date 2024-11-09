using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace IdentityAspNetCore.Models.ViewModels;

public class RegisterVM
{
    [Required]
    public string Name { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [DisplayName("Confirm password")]
    [Compare("Password", ErrorMessage = "The password and confirm password dont match")]
    public string ConfirmPassword { get; set; }

    [ValidateNever]
    public IEnumerable<SelectListItem>? RoleList { get; set; }
    public string Role { get; set; }
}
