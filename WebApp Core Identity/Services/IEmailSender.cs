using System.Threading.Tasks;

namespace WebApp_Core_Identity.Services
{
 public interface IEmailSender
 {
 Task SendEmailAsync(string to, string subject, string html);
 }
}
