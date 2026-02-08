using System.Threading.Tasks;
using WebApp_Core_Identity.Model;
using Microsoft.AspNetCore.Http;

namespace WebApp_Core_Identity.Services
{
 public interface IAuditService
 {
 Task LogEventAsync(string userId, string eventType, string description, HttpContext httpContext = null);
 }
}
