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

namespace WebApp_Core_Identity.Pages
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        [BindProperty]
        public Login LModel { get; set; }

        [BindProperty]
        public string gRecaptchaToken { get; set; }

        public string RecaptchaSiteKey { get; private set; }

        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IConfiguration configuration;
        private readonly IRecaptchaService recaptchaService;

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IConfiguration configuration, IRecaptchaService recaptchaService)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.configuration = configuration;
            this.recaptchaService = recaptchaService;
        }
        public void OnGet()
        {
            RecaptchaSiteKey = configuration.GetValue<string>("Recaptcha:SiteKey");

            if (Request.Query.ContainsKey("sessionExpired"))
                ViewData["SessionMessage"] = "Your session has expired. Please log in again.";
            if (Request.Query.ContainsKey("otherLogin"))
                ViewData["SessionMessage"] = "Your session was ended because your account was signed in on another device.";
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

                // Enable lockout counting on failed attempts
                var check = await signInManager.CheckPasswordSignInAsync(user, LModel.Password, lockoutOnFailure: true);
                if (check.Succeeded)
                {
                    // create a session id and register it with the session tracker
                    var sessionTracker = HttpContext.RequestServices.GetRequiredService<ISessionTracker>();
                    var sessionId = Guid.NewGuid().ToString();
                    var timeoutMinutes = configuration.GetValue<int>("Session:TimeoutMinutes",20);
                    var sessionTimeout = TimeSpan.FromMinutes(timeoutMinutes); // keep in sync with cookie expiration
                    sessionTracker.CreateSession(user.Id, sessionId, sessionTimeout);

                    // create principal and add session id claim
                    var principal = await signInManager.CreateUserPrincipalAsync(user);
                    if (principal.Identity is ClaimsIdentity ci)
                    {
                        ci.AddClaim(new Claim("SessionId", sessionId));
                    }

                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = LModel.RememberMe,
                        ExpiresUtc = DateTimeOffset.UtcNow.Add(sessionTimeout),
                        AllowRefresh = true
                    };

                    // sign in using Identity application scheme
                    await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal, authProperties);

                    return RedirectToPage("Index");
                }

                if (check.IsLockedOut)
                {
                    ModelState.AddModelError("", "Account locked due to multiple failed login attempts. Please try again later.");
                }
                else if (check.IsNotAllowed)
                {
                    ModelState.AddModelError("", "Login is not allowed for this account. Please confirm your email or contact support.");
                }
                else if (check.RequiresTwoFactor)
                {
                    ModelState.AddModelError("", "Two-factor authentication is required for this account.");
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
