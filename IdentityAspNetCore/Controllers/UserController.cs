using IdentityAspNetCore.Data;
using IdentityAspNetCore.Models;
using IdentityAspNetCore.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityAspNetCore.Controllers;

public class UserController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    public UserController(ApplicationDbContext db, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        _db = db;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public async Task<IActionResult> Index()
    {
        var userList = _db.ApplicationUsers.ToList();

        foreach (var user in userList)
        {
            var userRoles = await _userManager.GetRolesAsync(user);
            
            var userClaims = await _userManager.GetClaimsAsync(user);   

            user.Role = string.Join(", ", userRoles);
            user.Claim = string.Join(", ", userClaims.Select(l => l.Type));
        }

        return View(userList);
    }


    [HttpGet]
    public async Task<IActionResult> ManageRoles(string userId)
    {
        ApplicationUser user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return NotFound();
        }

        RolesVM model = new()
        {
            User = user,
        };

        var existingRoles = await _userManager.GetRolesAsync(user);

        foreach(var role in _roleManager.Roles)
        {
            RoleSelection roleSelection = new()
            {
                RoleName = role.Name
            };

            if (existingRoles.Any(l => l == role.Name))
            {
                roleSelection.IsSelected = true;
            }

            model.RolesList.Add(roleSelection);
        }

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ManageRoles(RolesVM model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByIdAsync(model.User.Id);

            var existingRoles = await _userManager.GetRolesAsync(user);

            var result = await _userManager.RemoveFromRolesAsync(user, existingRoles);

            if (!result.Succeeded)
            {
                return View(model);
            }

            result = await _userManager.AddToRolesAsync(user, model.RolesList.Where(l => l.IsSelected).Select(l => l.RoleName));

            if (!result.Succeeded)
            {
                return View(model);
            }

            return RedirectToAction(nameof(Index));   
        }

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> ManageClaims(string userId)
    {
        ApplicationUser user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var existingUserClaims = await _userManager.GetClaimsAsync(user);

        var model = new ClaimsVM()
        {
            User = user
        };

        foreach (Claim claim in ClaimStore.claimsList)
        {
            ClaimSelection userClaim = new()
            {
                ClaimType = claim.Type,
            };

            if (existingUserClaims.Any(l => l.Type == claim.Type))
            {
                userClaim.IsSelected = true;
            }

            model.ClaimList.Add(userClaim);
        }

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ManageClaims(ClaimsVM claimsVM)
    {
        ApplicationUser user = await _userManager.FindByIdAsync(claimsVM.User.Id);
        if (user == null)
        {
            return NotFound();
        }

        var oldUserClaims = await _userManager.GetClaimsAsync(user);

        var result = await _userManager.RemoveClaimsAsync(user, oldUserClaims);

        if (!result.Succeeded)
        {
            return View(claimsVM);
        }

        result = await _userManager.AddClaimsAsync(user,
            claimsVM.ClaimList.Where(l => l.IsSelected).Select(x => new Claim(x.ClaimType, x.IsSelected.ToString())));

        if (!result.Succeeded)
        {
            return View(claimsVM);
        }

        return RedirectToAction("Index");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LockUnlock(string? userId)
    {
        ApplicationUser user = _db.ApplicationUsers.FirstOrDefault(l => l.Id == userId);
        if (user == null)
        {
            return NotFound();
        }

        if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
        {
            user.LockoutEnd = DateTime.Now;
            //unlock the user
        }
        else
        {
            user.LockoutEnd = DateTime.Now.AddYears(100);
            //lock the user
        }

        await _db.SaveChangesAsync();

        return RedirectToAction("Index");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> TwoFactorAuth(string? userId)
    {
        ApplicationUser user = _db.ApplicationUsers.FirstOrDefault(l => l.Id == userId);
        if (user == null)
        {
            return NotFound();
        }

        if (user.TwoFactorEnabled)
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);

            await _userManager.SetTwoFactorEnabledAsync(user, false);
        }
  
        await _db.SaveChangesAsync();

        return RedirectToAction("Index");
    }
}
