using IdentityAspNetCore.Controllers;
using IdentityAspNetCore.Data;
using IdentityAspNetCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Moq;
using System.Security.Claims;
using Xunit;

namespace IdentityAspNetCoreTests;

public class UserControllerTests
{
    private DbContextOptions<ApplicationDbContext> options;

    public UserControllerTests()
    {
        options = new DbContextOptionsBuilder<ApplicationDbContext>()
          .UseInMemoryDatabase(databaseName: "TestDatabase").Options;
    }

    [Fact]
    public async Task Index_ShouldReturnViewWithListOfUsers()
    {
        // Arrange
        var user1 = new ApplicationUser() { Id = "1", Name = "" };
        var user2 = new ApplicationUser() { Id = "2", Name = "" };

        using (var context = new ApplicationDbContext(options))
        {
            context.ApplicationUsers.Add(user1);
            context.ApplicationUsers.Add(user2);

            context.SaveChanges();

            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(context), null, null, null, null, null, null, null, null);
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(context), null, null, null, null);

            var controller = new UserController(context, userManager, roleManager);

            // Act
            var result = await controller.Index();

            // Assert
            Assert.NotNull(result);
            Assert.IsType<ViewResult>(result);
            var viewResult = result as ViewResult;
            Assert.NotNull(viewResult.Model);

            var userList = viewResult.Model as List<ApplicationUser>;
            Assert.NotNull(userList);
        }
    }
}


