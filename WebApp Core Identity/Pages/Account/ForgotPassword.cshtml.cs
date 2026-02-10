using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApp_Core_Identity.Model;
using WebApp_Core_Identity.Services;

namespace WebApp_Core_Identity.Pages.Account
{
 public class ForgotPasswordModel : PageModel
 {
 private readonly UserManager<ApplicationUser> userManager;
 private readonly IEmailSender emailSender;

 [BindProperty]
 public string Email { get; set; }

 public ForgotPasswordModel(UserManager<ApplicationUser> userManager, IEmailSender emailSender)
 {
 this.userManager = userManager;
 this.emailSender = emailSender;
 }

 public void OnGet() { }

 public async Task<IActionResult> OnPostAsync()
 {
 if (string.IsNullOrEmpty(Email))
 {
 ModelState.AddModelError("", "Please enter your email.");
 return Page();
 }
 var user = await userManager.FindByEmailAsync(Email);
 if (user == null)
 {
 // Do not reveal user existence
 return RedirectToPage("/Account/ForgotPasswordConfirmation");
 }
 var token = await userManager.GeneratePasswordResetTokenAsync(user);
 var callback = Url.Page("/Account/ResetPassword", null, new { userId = user.Id, code = System.Net.WebUtility.UrlEncode(token) }, Request.Scheme);
 await emailSender.SendEmailAsync(Email, "Reset your password", $"Please reset your password by <a href=\"{callback}\">clicking here</a>");
 return RedirectToPage("/Account/ForgotPasswordConfirmation");
 }
 }
}
