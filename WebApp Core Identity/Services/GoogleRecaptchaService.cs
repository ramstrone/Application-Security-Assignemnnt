using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace WebApp_Core_Identity.Services
{
 public class GoogleRecaptchaService : IRecaptchaService
 {
 private readonly IHttpClientFactory httpClientFactory;
 private readonly string secret;
 private readonly double minimumScore;

 public GoogleRecaptchaService(IHttpClientFactory httpClientFactory, IConfiguration config)
 {
 this.httpClientFactory = httpClientFactory;
 secret = config.GetValue<string>("Recaptcha:SecretKey");
 minimumScore = config.GetValue<double>("Recaptcha:MinimumScore",0.5);
 }

 private record RecaptchaResponse(bool success, double score, string action, string challenge_ts, string hostname, string[] error_codes);

 public async Task<bool> IsRequestValidAsync(string token, string remoteIp = null)
 {
 if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(secret))
 return false;

 var client = httpClientFactory.CreateClient();
 var url = $"https://www.google.com/recaptcha/api/siteverify?secret={secret}&response={token}" + (string.IsNullOrEmpty(remoteIp) ? string.Empty : $"&remoteip={remoteIp}");
 var resp = await client.GetFromJsonAsync<RecaptchaResponse>(url);
 if (resp == null) return false;
 if (!resp.success) return false;
 return resp.score >= minimumScore;
 }
 }
}
