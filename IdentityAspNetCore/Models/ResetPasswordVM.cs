using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace IdentityAspNetCore.Models;

public class ResetPasswordVM
{
    public string Code { get; set; }

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
}
