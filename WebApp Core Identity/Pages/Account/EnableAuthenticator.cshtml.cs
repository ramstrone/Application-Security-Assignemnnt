using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using WebApp_Core_Identity.Model;

namespace WebApp_Core_Identity.Pages.Account
{
    [Authorize]
    public class EnableAuthenticatorModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<EnableAuthenticatorModel> _logger;

        public EnableAuthenticatorModel(UserManager<ApplicationUser> userManager, ILogger<EnableAuthenticatorModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        public string? SharedKey { get; private set; }
        public string? AuthenticatorUri { get; private set; }

        [BindProperty]
        public string? Code { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            SharedKey = unformattedKey;
            var email = UrlEncoder.Default.Encode(user.Email ?? user.UserName ?? string.Empty);
            var issuer = UrlEncoder.Default.Encode("App Sec ASSN");
            AuthenticatorUri = $"otpauth://totp/{issuer}:{email}?secret={SharedKey}&issuer={issuer}&digits=6";
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            if (string.IsNullOrWhiteSpace(Code))
            {
                ModelState.AddModelError(string.Empty, "Please enter the verification code.");
                await OnGetAsync();
                return Page();
            }

            var verificationCode = Code.Replace(" ", string.Empty).Replace("-", string.Empty);
            var valid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, verificationCode);
            if (!valid)
            {
                ModelState.AddModelError(string.Empty, "Invalid verification code.");
                await OnGetAsync();
                return Page();
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            TempData["RecoveryCodes"] = string.Join(",", recoveryCodes);
            _logger.LogInformation("User {UserId} enabled authenticator app.", user.Id);
            return RedirectToPage("/Account/ShowRecoveryCodes");
        }
    }
}
