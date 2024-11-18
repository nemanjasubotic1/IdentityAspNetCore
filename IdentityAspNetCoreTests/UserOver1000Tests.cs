using IdentityAspNetCore.Data;
using IdentityAspNetCore.Models;
using IdentityAspNetCore.Services;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IdentityAspNetCoreTests;

public class UserOver1000Tests
{
    private DbContextOptions<ApplicationDbContext> options;
    public UserOver1000Tests()
    {
        options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: "Test_Db").Options;
    }

    [Fact]
    public void GetDays_InputUserId_ReturnsNumberOfDays()
    {
        // Arrange
        ApplicationUser user = new()
        {
            Id = "one",
            UserName = "user_name",
            Name = "",
            DateCreated = DateTime.UtcNow.AddDays(-10),
        };


        using (var context = new ApplicationDbContext(options))
        {
            UserOver1000 _userOver1000 = new UserOver1000(context);

            context.ApplicationUsers.Add(user);
            context.SaveChanges();

            var userFromDb = context.ApplicationUsers.FirstOrDefault(l => l.UserName == "user_name");

            // Act
            var result = _userOver1000.GetDays("one");

            // Assert
            Assert.Equal(10, result);
        }
    }

}
