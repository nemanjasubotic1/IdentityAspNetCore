using IdentityAspNetCore.Models;
using IdentityAspNetCore.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Text.Encodings.Web;

namespace IdentityAspNetCore.Controllers;

[Authorize]
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    private readonly SignInManager<ApplicationUser> _signInManager;

    private readonly RoleManager<IdentityRole> _roleManager;

    private readonly UrlEncoder _urlEncoder;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, UrlEncoder urlEncoder)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _urlEncoder = urlEncoder;
    }

    #region RegisterLoginLogout

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Register(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        if (!_roleManager.RoleExistsAsync(SD.Role_Admin).GetAwaiter().GetResult())
        {
            await _roleManager.CreateAsync(new IdentityRole(SD.Role_Admin));
            await _roleManager.CreateAsync(new IdentityRole(SD.Role_User));
            await _roleManager.CreateAsync(new IdentityRole(SD.Role_Guest));
        }

        var roleList = _roleManager.Roles.ToList();

        RegisterVM registerVM = new()
        {
            RoleList = roleList.Select(l => new SelectListItem
            {
                Value = l.Name,
                Text = l.Name,
            })
        };

        return View(registerVM);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterVM model, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        returnUrl ??= Url.Content("~/");

        if (ModelState.IsValid)
        {
            ApplicationUser user = new()
            {
                Name = model.Name,
                UserName = model.Email,
                Email = model.Email,
                NormalizedEmail = model.Email.ToUpper(),
                DateCreated = DateTime.Now,
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                if (model.Role != null && model.Role.Length > 0)
                {
                    await _userManager.AddToRoleAsync(user, model.Role);
                }
                else
                {
                    await _userManager.AddToRoleAsync(user, SD.Role_Guest);
                }

                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                var callbackUrl = Url.Action("EmailConfirmation", new
                {
                    code,
                    model.Email,
                });

                ViewData["callbackUrl"] = callbackUrl;

                return View(model);
            }

            AddErrors(result);
        }

        TempData["error"] = "Something is wrong";

        var roleList = _roleManager.Roles.ToList();

        RegisterVM registerVM = new()
        {
            RoleList = roleList.Select(l => new SelectListItem
            {
                Value = l.Name,
                Text = l.Name,
            })
        };

        return View(registerVM);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginVM model, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        returnUrl ??= Url.Content("~/");

        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                TempData["error"] = "Username name dont exists";

                return RedirectToAction(nameof(Login));
            }
            else
            {
                var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);

                if (isEmailConfirmed)
                {
                    return await SingInUserAsync(model, returnUrl);
                }
                else
                {
                    return RedirectToAction(nameof(ConfirmEmail), new { email = model.Email });
                }
            }
        }
        else
        {
            return View(model);
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogOff()
    {
        await _signInManager.SignOutAsync();

        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Error()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Lockout()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult AccessDenied()
    {
        return View();
    }

    #endregion

    #region TwoFactorAuthentication

    [HttpGet]
    // used in View Index, Home
    public async Task<IActionResult> EnableAuthenticator()
    {
        string AuthenticatedUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        var user = await _userManager.GetUserAsync(User);

        if (user != null)
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);

            var token = await _userManager.GetAuthenticatorKeyAsync(user);

            var authUri = string.Format(AuthenticatedUriFormat, _urlEncoder.Encode("IdentityManager"), _urlEncoder.Encode(user.Email), token);

            var model = new TwoFactorAuthenticationVM()
            {
                Token = token,
                QrCodeUrl = authUri
            };

            return View(model);
        }

        return View("Error");

    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationVM model)
    {
        var user = await _userManager.GetUserAsync(User);

        if (ModelState.IsValid)
        {
            var succeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

            if (succeded)
            {
                await _userManager.SetTwoFactorEnabledAsync(user, true);

                return RedirectToAction("AuthenticatorConfirmation");
            }
            else
            {
                ModelState.AddModelError("", "Two step verification could not be validated");
            }
        }

        return View("Error");
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyAuthenticatorCode(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

        if (user == null)
        {
            return View("Error");
        }

        VerifyAuthenticatorVM verifyAuthenticatorVM = new()
        {
            ReturnUrl = returnUrl
        };

        return View(verifyAuthenticatorVM);
    }

    [HttpGet]
    public async Task<IActionResult> RemoveAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);

        await _userManager.ResetAuthenticatorKeyAsync(user);

        await _userManager.SetTwoFactorEnabledAsync(user, false);

        return RedirectToAction(nameof(Index), "Home");
    }


    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorVM model)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

        if (ModelState.IsValid)
        {
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient: false);

            if (result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
        }

        ModelState.AddModelError("", "Invalid login attempt");
        return View(model);
    }

    [HttpGet]
    public IActionResult AuthenticatorConfirmation()
    {
        return View();
    }

    #endregion

    #region ForgotPasswordConfirmation

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordVM model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user == null)
        {
            return RedirectToAction("ForgotPasswordConfirmation");
        }

        var code = await _userManager.GeneratePasswordResetTokenAsync(user);

        var callbackUrl = Url.Action("ResetPassword", new
        {
            code,
            model.Email
        });

        ViewData["callbackUrl"] = callbackUrl; // fake email confirmation link

        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string? code = null, string? email = null)
    {
        return code == null ? View("Error") : View();
    }


    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(ResetPasswordVM model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return View("Error");
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            AddErrors(result);
        }

        ModelState.AddModelError("", "Something is not right, try again");

        return View(model);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation(string? code = null)
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    #endregion

    #region ConfirmEmail

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> EmailConfirmation(string? code = null, string? email = null)
    {

        ViewData["email"] = email;

        var user = await _userManager.FindByEmailAsync(email);

        if (user == null) return View("Error");

        var result = await _userManager.ConfirmEmailAsync(user, code);

        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);

            return View();
        }

        AddErrors(result);

        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string? email = null)
    {
        if (email == null) return View("Error");

        var user = await _userManager.FindByEmailAsync(email);

        if (user == null) return View("Error");

        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        var callbackUrl = Url.Action("EmailConfirmation", new
        {
            code,
            email,
        });

        ViewData["callbackUrl"] = callbackUrl;

        return View();
    }


    #endregion

    #region HelperMethods

    private void AddErrors(IdentityResult identityResult)
    {
        foreach (var error in identityResult.Errors)
        {
            ModelState.AddModelError("", error.Description);
        }
    }

    [HttpGet]
    [AllowAnonymous]
    private async Task<IActionResult> SingInUserAsync(LoginVM model, string? returnUrl = null)
    {
        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, isPersistent: model.RememberMe, lockoutOnFailure: true);
        returnUrl ??= Url.Content("~/");

        if (result.Succeeded)
        {
            return LocalRedirect(returnUrl);
        }

        if (result.RequiresTwoFactor)
        {
            return RedirectToAction("VerifyAuthenticatorCode", new { returnUrl });
        }

        if (result.IsLockedOut)
        {
            return View("Lockout");
        }

        TempData["error"] = "Invalid login, check your credentials";

        return View(model);
    }


    #endregion
}
