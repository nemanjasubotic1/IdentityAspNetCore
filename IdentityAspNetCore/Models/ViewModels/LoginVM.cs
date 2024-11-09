using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace IdentityAspNetCore.Models.ViewModels;

public class LoginVM
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [DisplayName("Remember me?")]
    public bool RememberMe { get; set; }
}
