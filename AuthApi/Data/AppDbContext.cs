using Microsoft.EntityFrameworkCore;
using AuthApi.Models;

namespace AuthApi.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<User> Users => Set<User>();
        public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();
        public DbSet<Session> Sessions => Set<Session>();
        public DbSet<ActivityLog> ActivityLogs => Set<ActivityLog>();
        public DbSet<RevokedToken> RevokedTokens => Set<RevokedToken>();
    }
}