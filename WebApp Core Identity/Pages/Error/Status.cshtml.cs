using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace WebApp_Core_Identity.Pages.Error
{
    public class StatusModel : PageModel
    {
        private readonly ILogger<StatusModel> logger;
        public int StatusCode { get; private set; }
        public string? Message { get; private set; }
        public string? RequestPath { get; private set; }

        public StatusModel(ILogger<StatusModel> logger)
        {
            this.logger = logger;
        }

        public void OnGet(int statusCode)
        {
            StatusCode = statusCode;
            RequestPath = HttpContext.Request.Path;
            Message = statusCode switch
            {
                404 => "The page you requested was not found.",
                403 => "You do not have permission to access this resource.",
                401 => "Authentication is required to access this resource.",
                500 => "An unexpected server error occurred.",
                _ => "An error occurred while processing your request."
            };

            // Sanitize user-controlled values before logging to avoid log injection (CRLF/control chars)
            var safePath = SanitizeForLogging(RequestPath);

            // Use structured logging (no string concatenation) and the sanitized value
            logger.LogWarning("Status {status} returned for {path}", statusCode, safePath);
        }

        private static string SanitizeForLogging(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            var sb = new StringBuilder(value.Length);
            foreach (var ch in value)
            {
                if (ch == '\r')
                    sb.Append("\\r");
                else if (ch == '\n')
                    sb.Append("\\n");
                else if (char.IsControl(ch))
                    sb.Append('?'); // replace other control characters
                else
                    sb.Append(ch);
            }
            return sb.ToString();
        }
    }
}
