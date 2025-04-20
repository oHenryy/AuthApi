using AuthApi.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Services
{
    public class SessionCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;

        public SessionCleanupService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                using var scope = _serviceProvider.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                var expiradas = await db.Sessions
                    .Where(s => s.ExpiresAt < DateTime.UtcNow)
                    .ToListAsync();

                if (expiradas.Any())
                {
                    db.Sessions.RemoveRange(expiradas);
                    await db.SaveChangesAsync();
                }

                await Task.Delay(TimeSpan.FromMinutes(10), stoppingToken);
            }
        }
    }
}
