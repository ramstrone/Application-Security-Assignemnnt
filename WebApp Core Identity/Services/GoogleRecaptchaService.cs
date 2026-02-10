using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.Collections.Generic;

namespace WebApp_Core_Identity.Services
{
 public class GoogleRecaptchaService : IRecaptchaService
 {
 private readonly IHttpClientFactory httpClientFactory;
 private readonly string secret;
 private readonly double minimumScore;
 private readonly ILogger<GoogleRecaptchaService> logger;

 public GoogleRecaptchaService(IHttpClientFactory httpClientFactory, IConfiguration config, ILogger<GoogleRecaptchaService> logger)
 {
 this.httpClientFactory = httpClientFactory;
 secret = config.GetValue<string>("Recaptcha:SecretKey");
 minimumScore = config.GetValue<double>("Recaptcha:MinimumScore",0);
 this.logger = logger;
 }

 public async Task<bool> IsRequestValidAsync(string token, string remoteIp = null)
 {
 if (string.IsNullOrEmpty(token))
 {
 logger.LogWarning("reCAPTCHA token is empty.");
 return false;
 }
 if (string.IsNullOrEmpty(secret))
 {
 logger.LogWarning("reCAPTCHA secret is not configured.");
 return false;
 }

 var client = httpClientFactory.CreateClient();
 var request = new HttpRequestMessage(HttpMethod.Post, "https://www.google.com/recaptcha/api/siteverify");
 var form = new List<KeyValuePair<string, string>>
 {
 new KeyValuePair<string, string>("secret", secret),
 new KeyValuePair<string, string>("response", token)
 };
 if (!string.IsNullOrEmpty(remoteIp))
 {
 form.Add(new KeyValuePair<string, string>("remoteip", remoteIp));
 }

 request.Content = new FormUrlEncodedContent(form);

 string respStr;
 try
 {
 var resp = await client.SendAsync(request);
 respStr = await resp.Content.ReadAsStringAsync();
 }
 catch (HttpRequestException ex)
 {
 logger.LogError(ex, "Failed to call Google siteverify endpoint.");
 return false;
 }

 logger.LogInformation("reCAPTCHA verify raw response: {resp}", respStr);

 try
 {
 using var doc = JsonDocument.Parse(respStr);
 var root = doc.RootElement;

 var success = root.TryGetProperty("success", out var s) && s.GetBoolean();
 if (!success)
 {
 if (root.TryGetProperty("error-codes", out var errors))
 {
 logger.LogWarning("reCAPTCHA verification failed, error-codes: {errors}", errors.ToString());
 }
 if (root.TryGetProperty("hostname", out var hostEl))
 {
 logger.LogInformation("reCAPTCHA hostname: {hostname}", hostEl.GetString());
 }
 return false;
 }

 var score = root.TryGetProperty("score", out var scoreEl) ? scoreEl.GetDouble() :0.0;
 var hostname = root.TryGetProperty("hostname", out var h) ? h.GetString() : null;
 logger.LogInformation("reCAPTCHA success. score={score}, hostname={hostname}", score, hostname);

 return score >= minimumScore;
 }
 catch (JsonException ex)
 {
 logger.LogError(ex, "Failed to parse reCAPTCHA response JSON.");
 return false;
 }
 }
 }
}
