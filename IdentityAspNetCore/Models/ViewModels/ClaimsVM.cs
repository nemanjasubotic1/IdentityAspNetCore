namespace IdentityAspNetCore.Models.ViewModels
{
    public class ClaimsVM
    {
        public ClaimsVM()
        {
            ClaimList = [];
        }

        public List<ClaimSelection> ClaimList { get; set; }
        public ApplicationUser User { get; set; }
    }

    public class ClaimSelection
    {
        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }
}
