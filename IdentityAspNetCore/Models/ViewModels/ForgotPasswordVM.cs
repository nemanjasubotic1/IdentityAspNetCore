using System.ComponentModel.DataAnnotations;

namespace IdentityAspNetCore.Models.ViewModels;

public class ForgotPasswordVM
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
