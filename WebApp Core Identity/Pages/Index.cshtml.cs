using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using WebApp_Core_Identity.Model;
using WebApp_Core_Identity.Services;

namespace WebApp_Core_Identity.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly ICreditCardProtector creditCardProtector;

        public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager, ICreditCardProtector creditCardProtector)
        {
            _logger = logger;
            this.userManager = userManager;
            this.creditCardProtector = creditCardProtector;
        }

        public string Email { get; set; }
        public string FullName { get; set; }
        public string MobileNumber { get; set; }
        public string BillingAddress { get; set; }
        public string ShippingAddress { get; set; }
        public string MaskedCreditCard { get; set; }
        public string PhotoUrl { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            Email = user.Email;
            FullName = $"{user.FirstName} {user.LastName}".Trim();
            MobileNumber = user.MobileNumber;
            BillingAddress = user.BillingAddress;
            ShippingAddress = user.ShippingAddress;

            MaskedCreditCard = string.Empty;
            if (!string.IsNullOrEmpty(user.CreditCardNo))
            {
                MaskedCreditCard = creditCardProtector.Mask(user.CreditCardNo);
            }

            PhotoUrl = null;
            if (!string.IsNullOrEmpty(user.PhotoPath))
            {
                PhotoUrl = Url.Content("~/uploads/" + user.PhotoPath);
            }

            return Page();
        }
    }
}
