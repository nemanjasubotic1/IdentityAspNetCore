using IdentityAspNetCore.Models;
using IdentityAspNetCore.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Text.Encodings.Web;

namespace IdentityAspNetCore.Controllers;

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

    [HttpGet]
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
                NormalizedEmail = model.Email.ToUpper()
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

                await _signInManager.SignInAsync(user, isPersistent: false);

                return LocalRedirect(returnUrl);
            }

            AddErrors(result);
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

    [HttpGet]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        return View();

    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginVM model, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        returnUrl ??= Url.Content("~/");

        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, isPersistent: model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }

            if (result.RequiresTwoFactor)
            {
                return RedirectToAction("VerifyAuthenticatorCode", new { returnUrl = returnUrl });
            }

            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
        }
        else
        {
            ModelState.AddModelError("", "Invalid login attempt");
            return View(model);
        }

        return View(model);
    }


    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogOff()
    {
        await _signInManager.SignOutAsync();

        return RedirectToAction("Index", "Home");
    }

    #region TwoFactorAuthentication

    [HttpGet]
    public async Task<IActionResult> EnableAuthenticator()
    {
        // standard in defining qr code used by TOTP-compatible apps (google authenticator, microsoft authenticator...)
        string AuthenticatedUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        var user = await _userManager.GetUserAsync(User);

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

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorVM model)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

        if (!ModelState.IsValid) return View(model);
        
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient: false);

            if (result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                return View("Lockout");
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

    [HttpGet]
    public IActionResult Error()
    {
        return View();
    }

    #region HelperMethods

    private void AddErrors(IdentityResult identityResult)
    {
        foreach (var error in identityResult.Errors)
        {
            ModelState.AddModelError("", error.Description);
        }
    }

    #endregion
}
