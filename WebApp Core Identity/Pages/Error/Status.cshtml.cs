using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;

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

            logger.LogWarning("Status {status} returned for {path}", statusCode, RequestPath);
        }
    }
}
