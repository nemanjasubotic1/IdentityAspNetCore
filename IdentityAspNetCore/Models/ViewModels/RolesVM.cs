namespace IdentityAspNetCore.Models.ViewModels
{
    public class RolesVM
    {
        public RolesVM()
        {
            RolesList = [];
        }
        public List<RoleSelection> RolesList { get; set; }
        public ApplicationUser User { get; set; }
    }

    public class RoleSelection
    {
        public string RoleName { get; set; }
        public bool IsSelected { get; set; }
    }
}
