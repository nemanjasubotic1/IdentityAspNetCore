using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAspNetCore.Controllers;

public class PolicyCheckerController : Controller
{
    [Authorize(Policy = "AdminCreate")]
    public IActionResult Admin_Create()
    {
        return View();
    }


    [Authorize(Policy = "UserOver1000")]
    public IActionResult UserOver1000Days()
    {
        return View();
    }
}
