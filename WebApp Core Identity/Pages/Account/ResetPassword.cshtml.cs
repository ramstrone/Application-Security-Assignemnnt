using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApp_Core_Identity.Model;
using WebApp_Core_Identity.Services;

namespace WebApp_Core_Identity.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IPasswordHistoryService passwordHistory;

        [BindProperty]
        public string? UserId { get; set; }
        [BindProperty]
        public string? Code { get; set; }
        [BindProperty]
        public string? NewPassword { get; set; }
        [BindProperty]
        public string? ConfirmPassword { get; set; }

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, IPasswordHistoryService passwordHistory)
        {
            this.userManager = userManager;
            this.passwordHistory = passwordHistory;
        }

        public void OnGet(string userId, string code)
        {
            UserId = userId;
            Code = code;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (NewPassword != ConfirmPassword)
            {
                ModelState.AddModelError("", "Passwords do not match.");
                return Page();
            }
            if (string.IsNullOrEmpty(UserId) || string.IsNullOrEmpty(Code))
            {
                ModelState.AddModelError("", "Invalid password reset request.");
                return Page();
            }
            var user = await userManager.FindByIdAsync(UserId);
            if (user == null) return RedirectToPage("/Account/ResetPasswordConfirmation");
            var historyLimit = int.Parse("2");
            if (await passwordHistory.IsInHistoryAsync(user, NewPassword ?? string.Empty, historyLimit))
            {
                ModelState.AddModelError("", "You cannot reuse a recent password.");
                return Page();
            }
            var decoded = System.Net.WebUtility.UrlDecode(Code);
            var result = await userManager.ResetPasswordAsync(user, decoded, NewPassword);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors) ModelState.AddModelError("", e.Description);
                return Page();
            }
            user.PasswordChangedUtc = DateTime.UtcNow;
            await userManager.UpdateAsync(user);
            var updated = await userManager.FindByIdAsync(user.Id);
            var hash = updated?.PasswordHash;
            if (!string.IsNullOrEmpty(hash))
            {
                await passwordHistory.AddAsync(user.Id, hash);
                await passwordHistory.TrimAsync(user.Id, historyLimit);
            }
            return RedirectToPage("/Account/ResetPasswordConfirmation");
        }
    }
}
