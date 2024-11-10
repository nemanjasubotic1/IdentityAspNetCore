using System.ComponentModel.DataAnnotations;

namespace IdentityAspNetCore.Models.ViewModels;

public class ConfirmEmailVM
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    public string Code { get; set; }
}
