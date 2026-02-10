using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WebApp_Core_Identity.Services
{
 public class LogEmailSender : IEmailSender
 {
 private readonly ILogger<LogEmailSender> logger;
 public LogEmailSender(ILogger<LogEmailSender> logger) => this.logger = logger;
 public Task SendEmailAsync(string to, string subject, string html)
 {
 logger.LogInformation("Email to {to} subject {subject}: {body}", to, subject, html);
 return Task.CompletedTask;
 }
 }
}
