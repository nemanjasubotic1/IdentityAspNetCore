namespace IdentityAspNetCore.Models.ViewModels;

public class TwoFactorAuthenticationVM
{
    public string Code { get; set; }
    public string? Token { get; set; }
    public string? QrCodeUrl { get; set; }
}
