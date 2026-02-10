using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApp_Core_Identity.Model
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
        {
        }

        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // If you enable RequireUniqueEmail = true in IdentityOptions,
            // enforce a unique index at the DB level on NormalizedEmail.
            builder.Entity<ApplicationUser>()
                .HasIndex(u => u.NormalizedEmail)
                .IsUnique();

            builder.Entity<AuditLog>()
                .HasIndex(a => a.CreatedAt);

            builder.Entity<PasswordHistory>()
                .HasIndex(p => new { p.UserId, p.CreatedAtUtc });
        }
    }
}
