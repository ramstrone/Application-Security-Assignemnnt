using System.Threading.Tasks;

namespace WebApp_Core_Identity.Services
{
 public interface IRecaptchaService
 {
 Task<bool> IsRequestValidAsync(string token, string remoteIp = null);
 }
}
