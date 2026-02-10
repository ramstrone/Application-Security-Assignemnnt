using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using WebApp_Core_Identity.Model;

namespace WebApp_Core_Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginWith2faModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LoginWith2faModel> _logger;

        public LoginWith2faModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginWith2faModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        public string? TwoFactorCode { get; set; }

        [BindProperty]
        public bool RememberMe { get; set; }

        [BindProperty]
        public bool RememberMachine { get; set; }

        public void OnGet(bool rememberMe = false)
        {
            RememberMe = rememberMe;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            _logger.LogInformation("GetTwoFactorAuthenticationUserAsync returned userId={userId}", user?.Id);

            if (user == null)
            {
                // No user in 2FA flow; go back to login
                _logger.LogWarning("No user found in 2FA flow; redirecting to login.");
                return RedirectToPage("/Login");
            }

            var code = (TwoFactorCode ?? string.Empty).Replace(" ", string.Empty).Replace("-", string.Empty);

            // Try authenticator app code
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, RememberMe, RememberMachine);
            _logger.LogInformation("TwoFactorAuthenticatorSignInAsync result: Succeeded={s} IsLockedOut={l} RequiresTwoFactor={r}", result.Succeeded, result.IsLockedOut, result.RequiresTwoFactor);

            if (result.Succeeded)
            {
                _logger.LogInformation("2FA succeeded for user {userId}", user.Id);
                return RedirectToPage("/Index");
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Account is locked.");
                return Page();
            }

            // Try recovery code as fallback
            var recoveryResult = await _signInManager.TwoFactorRecoveryCodeSignInAsync(code);
            _logger.LogInformation("TwoFactorRecoveryCodeSignInAsync result: Succeeded={s} IsLockedOut={l}", recoveryResult.Succeeded, recoveryResult.IsLockedOut);
            if (recoveryResult.Succeeded)
            {
                return RedirectToPage("/Index");
            }

            ModelState.AddModelError(string.Empty, "Invalid two-factor code.");
            return Page();
        }
    }
}
