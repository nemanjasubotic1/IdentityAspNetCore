using Microsoft.AspNetCore.Mvc;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentityAspNetCore.Models.ViewModels;

public class VerifyAuthenticatorVM
{
    [Required]
    public string Code { get; set; }
    public string ReturnUrl { get; set; }
    [DisplayName("Remeber me?")]
    public bool RememberMe { get; set; }


}
