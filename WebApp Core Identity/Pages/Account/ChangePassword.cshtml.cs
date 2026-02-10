using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using WebApp_Core_Identity.Model;
using WebApp_Core_Identity.Services;

namespace WebApp_Core_Identity.Pages.Account
{
 public class ChangePasswordModel : PageModel
 {
 private readonly UserManager<ApplicationUser> userManager;
 private readonly SignInManager<ApplicationUser> signInManager;
 private readonly IPasswordHistoryService passwordHistory;
 private readonly IConfiguration configuration;

 [BindProperty]
 public string? OldPassword { get; set; }
 [BindProperty]
 public string? NewPassword { get; set; }
 [BindProperty]
 public string? ConfirmPassword { get; set; }

 public ChangePasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IPasswordHistoryService passwordHistory, IConfiguration configuration)
 {
 this.userManager = userManager;
 this.signInManager = signInManager;
 this.passwordHistory = passwordHistory;
 this.configuration = configuration;
 }

 public void OnGet()
 {
 }

 public async Task<IActionResult> OnPostAsync()
 {
 var user = await userManager.GetUserAsync(User);
 if (user == null) return Challenge();

 var minMinutes = configuration.GetValue<int>("PasswordPolicy:MinChangeMinutes",5);
 if (user.PasswordChangedUtc.HasValue && DateTime.UtcNow - user.PasswordChangedUtc.Value < TimeSpan.FromMinutes(minMinutes))
 {
 ModelState.AddModelError("", $"You must wait {minMinutes} minutes between password changes.");
 return Page();
 }

 if (string.IsNullOrEmpty(NewPassword) || string.IsNullOrEmpty(ConfirmPassword) || NewPassword != ConfirmPassword)
 {
 ModelState.AddModelError("", "New password and confirmation do not match.");
 return Page();
 }

 var historyLimit = configuration.GetValue<int>("PasswordPolicy:HistoryLimit",2);
 if (await passwordHistory.IsInHistoryAsync(user, NewPassword, historyLimit))
 {
 ModelState.AddModelError("", "You cannot reuse a recently used password.");
 return Page();
 }

 var change = await userManager.ChangePasswordAsync(user, OldPassword ?? string.Empty, NewPassword);
 if (!change.Succeeded)
 {
 foreach (var e in change.Errors) ModelState.AddModelError("", e.Description);
 return Page();
 }

 user.PasswordChangedUtc = DateTime.UtcNow;
 await userManager.UpdateAsync(user);

 // Get updated hash from store
 var updated = await userManager.FindByIdAsync(user.Id);
 var hash = updated?.PasswordHash;
 if (!string.IsNullOrEmpty(hash))
 {
 await passwordHistory.AddAsync(user.Id, hash);
 await passwordHistory.TrimAsync(user.Id, historyLimit);
 }

 await signInManager.RefreshSignInAsync(user);
 return RedirectToPage("/Index");
 }
 }
}
