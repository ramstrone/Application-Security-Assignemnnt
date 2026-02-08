using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using WebApp_Core_Identity.Model;

namespace WebApp_Core_Identity.Pages
{
 [Authorize]
 public class AuditLogsModel : PageModel
 {
 private readonly AuthDbContext db;
 private readonly UserManager<ApplicationUser> userManager;

 public AuditLogsModel(AuthDbContext db, UserManager<ApplicationUser> userManager)
 {
 this.db = db;
 this.userManager = userManager;
 }

 public IList<AuditLog> Logs { get; set; } = Array.Empty<AuditLog>();
 public bool IsAdmin { get; set; }

 public async Task OnGetAsync()
 {
 var user = await userManager.GetUserAsync(User);
 if (user == null)
 {
 Logs = Array.Empty<AuditLog>();
 return;
 }

 IsAdmin = await userManager.IsInRoleAsync(user, "Admin");

 if (IsAdmin)
 {
 Logs = await db.AuditLogs
 .OrderByDescending(a => a.CreatedAt)
 .Take(200)
 .ToListAsync();
 }
 else
 {
 Logs = await db.AuditLogs
 .Where(a => a.UserId == user.Id)
 .OrderByDescending(a => a.CreatedAt)
 .Take(100)
 .ToListAsync();
 }
 }
 }
}
