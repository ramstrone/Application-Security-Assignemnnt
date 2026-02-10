using System.Threading.Tasks;
using WebApp_Core_Identity.Model;

namespace WebApp_Core_Identity.Services
{
    public interface IPasswordHistoryService
    {
        Task AddAsync(string userId, string passwordHash);
        Task<bool> IsInHistoryAsync(ApplicationUser user, string newPassword, int historyLimit);
        Task TrimAsync(string userId, int keepLatest);
    }
}
