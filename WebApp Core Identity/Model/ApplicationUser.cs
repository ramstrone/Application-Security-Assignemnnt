using Microsoft.AspNetCore.Identity;

namespace WebApp_Core_Identity.Model
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; }
        public string CreditCard { get; set; }
    }
}
