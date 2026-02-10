using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApp_Core_Identity.Model;

namespace WebApp_Core_Identity.Pages.Account
{
 [Authorize]
 public class ForgetTwoFactorModel : PageModel
 {
 private readonly SignInManager<ApplicationUser> _signInManager;

 public ForgetTwoFactorModel(SignInManager<ApplicationUser> signInManager)
 {
 _signInManager = signInManager;
 }

 public async Task<IActionResult> OnPostAsync()
 {
 await _signInManager.ForgetTwoFactorClientAsync();
 TempData["Message"] = "This device will no longer be remembered for two-factor authentication.";
 return RedirectToPage("/Index");
 }
 }
}
