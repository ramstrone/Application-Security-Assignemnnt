using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace WebApp_Core_Identity.Services
{
    public class SmtpOptions
    {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; } = 587;
        public bool UseSsl { get; set; } = true; // if true: StartTls on non-465, SslOnConnect on 465
        public string User { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string FromName { get; set; } = "App Sec ASSN";
        public string FromAddress { get; set; } = "noreply@example.test";
    }

    public class SmtpEmailSender : IEmailSender
    {
        private readonly SmtpOptions _opts;
        private readonly ILogger<SmtpEmailSender> _logger;

        public SmtpEmailSender(IOptions<SmtpOptions> options, ILogger<SmtpEmailSender> logger)
        {
            _opts = options.Value;
            _logger = logger;
        }

        public async Task SendEmailAsync(string to, string subject, string html)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_opts.FromName, _opts.FromAddress));
            message.To.Add(MailboxAddress.Parse(to));
            message.Subject = subject;
            message.Body = new BodyBuilder { HtmlBody = html }.ToMessageBody();

            // Choose correct SecureSocketOptions
            SecureSocketOptions socketOption;
            if (_opts.Port == 465)
                socketOption = SecureSocketOptions.SslOnConnect;
            else if (_opts.UseSsl)
                socketOption = SecureSocketOptions.StartTls;
            else
                socketOption = SecureSocketOptions.None;

            try
            {
                using var client = new SmtpClient();
                // Avoid XOAUTH2 if not supported
                client.AuthenticationMechanisms.Remove("XOAUTH2");

                await client.ConnectAsync(_opts.Host, _opts.Port, socketOption);

                if (!string.IsNullOrEmpty(_opts.User))
                {
                    await client.AuthenticateAsync(_opts.User, _opts.Password);
                }

                await client.SendAsync(message);
                await client.DisconnectAsync(true);

                _logger.LogInformation("SMTP email sent to {to}", to);
            }
            catch (Exception ex)
            {
                // Log error and the body so you can copy the reset link in dev
                _logger.LogError(ex, "Failed to send SMTP email to {to}", to);
                _logger.LogInformation("Email body (dev fallback): {html}", html);
                // Do not rethrow in production flow; caller can decide behavior.
            }
        }
    }
}