using AuthApi.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("admin")]
    [Authorize(Roles = "admin")]
    public class AdminController : ControllerBase
    {
        private readonly AppDbContext _context;

        public AdminController(AppDbContext context)
        {
            _context = context;
        }

        [HttpGet("users")]
        public async Task<IActionResult> GetUsers()
        {
            var users = await _context.Users
                .Select(u => new { u.Id, u.Username, u.Email, u.Role, u.EmailConfirmed })
                .ToListAsync();

            return Ok(users);
        }

        [HttpGet("sessions")]
        public async Task<IActionResult> GetAllSessions()
        {
            var sessions = await _context.Sessions
                .Include(s => s.User)
                .OrderByDescending(s => s.CreatedAt)
                .Select(s => new
                {
                    s.Id,
                    s.IpAddress,
                    s.Device,
                    s.CreatedAt,
                    s.ExpiresAt,
                    s.User.Username,
                    s.User.Email
                })
                .ToListAsync();

            return Ok(sessions);
        }

        [HttpGet("users/{id}/sessions")]
        public async Task<IActionResult> GetUserSessions(int id)
        {
            var sessions = await _context.Sessions
                .Where(s => s.UserId == id)
                .ToListAsync();

            return Ok(sessions);
        }

        [HttpGet("logs")]
        public async Task<IActionResult> GetLogs()
        {
            var logs = await _context.ActivityLogs
                .OrderByDescending(l => l.Timestamp)
                .Take(100)
                .ToListAsync();

            return Ok(logs);
        }
    }
}
