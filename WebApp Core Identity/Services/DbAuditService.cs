using System;
using System.Threading.Tasks;
using WebApp_Core_Identity.Model;
using Microsoft.AspNetCore.Http;

namespace WebApp_Core_Identity.Services
{
 public class DbAuditService : IAuditService
 {
 private readonly AuthDbContext db;
 public DbAuditService(AuthDbContext db)
 {
 this.db = db;
 }

 public async Task LogEventAsync(string userId, string eventType, string description, HttpContext httpContext = null)
 {
 var log = new AuditLog
 {
 UserId = userId,
 EventType = eventType,
 Description = description,
 IpAddress = httpContext?.Connection?.RemoteIpAddress?.ToString(),
 UserAgent = httpContext?.Request?.Headers["User-Agent"].ToString(),
 CreatedAt = DateTime.UtcNow
 };

 db.AuditLogs.Add(log);
 await db.SaveChangesAsync();
 }
 }
}
