using IdentityAspNetCore.Data;

namespace IdentityAspNetCore.Services;

public class UserOver1000 : IUserOver1000
{
    private readonly ApplicationDbContext _db;
    public UserOver1000(ApplicationDbContext db)
    {
        _db = db;
    }

    public int GetDays(string userId)
    {
        var user = _db.ApplicationUsers.FirstOrDefault(l => l.Id == userId);

        if (user != null && user.DateCreated != DateTime.MinValue)
        {
            return (DateTime.Now - user.DateCreated).Days;
        }

        return 0;
    }
}
