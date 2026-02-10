using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApp_Core_Identity.Model;

namespace WebApp_Core_Identity.Services
{
    public class PasswordHistoryService : IPasswordHistoryService
    {
        private readonly AuthDbContext db;
        private readonly IPasswordHasher<ApplicationUser> hasher;

        public PasswordHistoryService(AuthDbContext db, IPasswordHasher<ApplicationUser> hasher)
        {
            this.db = db;
            this.hasher = hasher;
        }

        public async Task AddAsync(string userId, string passwordHash)
        {
            var PH = new PasswordHistory { UserId = userId, PasswordHash = passwordHash, CreatedAtUtc = DateTime.UtcNow };
            db.PasswordHistories.Add(PH);
            await db.SaveChangesAsync();
        }

        public async Task<bool> IsInHistoryAsync(ApplicationUser user, string newPassword, int historyLimit)
        {
            var hist = await db.PasswordHistories
                .Where(h => h.UserId == user.Id)
                .OrderByDescending(h => h.CreatedAtUtc)
                .Take(historyLimit)
                .Select(h => h.PasswordHash)
                .ToListAsync();

            foreach (var oldHash in hist)
            {
                var result = hasher.VerifyHashedPassword(user, oldHash, newPassword);
                if (result != PasswordVerificationResult.Failed)
                    return true;
            }
            return false;
        }

        public async Task TrimAsync(string userId, int keepLatest)
        {
            var toRemove = await db.PasswordHistories
                .Where(h => h.UserId == userId)
                .OrderByDescending(h => h.CreatedAtUtc)
                .Skip(keepLatest)
                .ToListAsync();

            if (toRemove.Count > 0)
            {
                db.PasswordHistories.RemoveRange(toRemove);
                await db.SaveChangesAsync();
            }
        }
    }
}
