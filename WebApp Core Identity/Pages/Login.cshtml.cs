using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApp_Core_Identity.ViewModels;
using WebApp_Core_Identity.Model;
using Microsoft.AspNetCore.Authorization;
using WebApp_Core_Identity.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace WebApp_Core_Identity.Pages
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        [BindProperty]
        public Login LModel { get; set; }

        [BindProperty]
        public string? gRecaptchaToken { get; set; }

        [BindProperty]
        public string? MustChangePassword { get; set; }

        public string? RecaptchaSiteKey { get; private set; }

        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IConfiguration configuration;
        private readonly IRecaptchaService recaptchaService;
        private readonly ILogger<LoginModel> logger;

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IConfiguration configuration, IRecaptchaService recaptchaService, ILogger<LoginModel> logger)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.configuration = configuration;
            this.recaptchaService = recaptchaService;
            this.logger = logger;
        }
        public void OnGet()
        {
            RecaptchaSiteKey = configuration.GetValue<string>("Recaptcha:SiteKey");

            if (Request.Query.ContainsKey("sessionExpired"))
                ViewData["SessionMessage"] = "Your session has expired. Please log in again.";
            if (Request.Query.ContainsKey("otherLogin"))
                ViewData["SessionMessage"] = "Your session was ended because your account was signed in on another device.";

            if (Request.Query.ContainsKey("mustChangePassword"))
            {
                MustChangePassword = Request.Query["mustChangePassword"];
                ViewData["MustChangePassword"] = true;
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Validate reCAPTCHA first
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            var validRecaptcha = await recaptchaService.IsRequestValidAsync(gRecaptchaToken, ip);
            if (!validRecaptcha)
            {
                ModelState.AddModelError("", "Bot detection failed. Please try again.");
                RecaptchaSiteKey = configuration.GetValue<string>("Recaptcha:SiteKey");
                return Page();
            }

            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(LModel.Email);
                if (user == null)
                {
                    ModelState.AddModelError("", "Username or Password incorrect");
                    RecaptchaSiteKey = configuration.GetValue<string>("Recaptcha:SiteKey");
                    return Page();
                }

                var result = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    // If password age exceeded, redirect to ChangePassword page so user can update password.
                    var maxAgeMinutes = configuration.GetValue<int>("PasswordPolicy:MaxAgeMinutes",1);
                    var expired = !user.PasswordChangedUtc.HasValue || DateTime.UtcNow - user.PasswordChangedUtc.Value > TimeSpan.FromMinutes(maxAgeMinutes);
                    if (expired)
                    {
                        // Successful sign-in, but require change password. Redirect to ChangePassword page.
                        return RedirectToPage("/Account/ChangePassword", new { mustChangePassword =1 });
                    }

                    // signed in, create session tracker etc (optional: use CreateUserPrincipalAsync and sign in if you need custom claims)
                    return RedirectToPage("Index");
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("/Account/LoginWith2fa", new { rememberMe = LModel.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    ModelState.AddModelError("", "Account locked due to multiple failed login attempts. Please try again later.");
                }
                else
                {
                    ModelState.AddModelError("", "Username or Password incorrect");
                }
            }

            RecaptchaSiteKey = configuration.GetValue<string>("Recaptcha:SiteKey");
            return Page();
        }
    }
}
