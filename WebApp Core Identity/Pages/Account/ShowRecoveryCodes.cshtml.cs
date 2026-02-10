using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApp_Core_Identity.Model;

namespace WebApp_Core_Identity.Pages.Account
{
    public class ShowRecoveryCodesModel : PageModel
    {
        [TempData]
        public string? RecoveryCodes { get; set; }

        public List<string> Codes { get; private set; } = new();

        public IActionResult OnGet()
        {
            if (string.IsNullOrEmpty(RecoveryCodes))
            {
                return RedirectToPage("/Index");
            }

            Codes = RecoveryCodes.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();
            return Page();
        }
    }
}
