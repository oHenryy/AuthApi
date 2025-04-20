using System.Security.Cryptography;
using System.Text;
using AuthApi.Models;
using AuthApi.Data;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using AuthApi.Helpers;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.Services
{
    public class AuthService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _config;
        private readonly JwtTokenGenerator _tokenGenerator;
        private readonly EmailSender _emailSender;

        public AuthService(AppDbContext context, IConfiguration config, JwtTokenGenerator tokenGenerator, EmailSender emailSender)
        {
            _context = context;
            _config = config;
            _tokenGenerator = tokenGenerator;
            _emailSender = emailSender;
        }

        public async Task<bool> RegisterAsync(string username, string email, string password)
        {
            if (await _context.Users.AnyAsync(
                u => u.Username.ToLower() == username.ToLower() || u.Email.ToLower() == email.ToLower()))
                return false;

            if (!new EmailAddressAttribute().IsValid(email))
                return false;

            var passwordHash = HashPassword(password);
            var verificationToken = Guid.NewGuid().ToString();

            var role = username == "admin" ? "admin" : "user";
            var user = new User
            {
                Username = username,
                Email = email,
                PasswordHash = passwordHash,
                Role = role,
                EmailConfirmed = false,
                EmailVerificationToken = verificationToken
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            var link = $"https://localhost:7275/auth/confirm-email?token={verificationToken}";
            var html = $"<h3>Confirme seu e-mail</h3><p><a href='{link}'>Clique aqui para confirmar</a></p>";

            await _emailSender.SendEmailAsync(email, "Confirmação de E-mail", html);
            return true;
        }

        public async Task<User?> AuthenticateAsync(string login, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u =>
                u.Username.ToLower() == login.ToLower() || u.Email.ToLower() == login.ToLower());

            if (user == null || user.PasswordHash != HashPassword(password))
                return null;

            return user;
        }

        private string HashPassword(string password)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes);
        }

        public async Task<(string token, string refreshToken)?> RefreshTokenAsync(string accessToken, string refreshToken)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(accessToken);
            var username = jwt.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime < DateTime.UtcNow)
                return null;

            var newAccessToken = _tokenGenerator.GenerateToken(user);
            var newRefreshToken = _tokenGenerator.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _context.SaveChangesAsync();

            return (newAccessToken, newRefreshToken);
        }

        public async Task<bool> RevokeRefreshTokenAsync(string login)
        {
            var user = await GetUserByLoginAsync(login);

            user!.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;

            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> RequestPasswordResetAsync(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) return false;

            user.PasswordResetToken = Guid.NewGuid().ToString();
            user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1);
            await _context.SaveChangesAsync();

            var resetLink = $"https://localhost:7275/auth/reset-password?token={user.PasswordResetToken}";
            var html = $"<h3>Redefinição de senha</h3><p><a href='{resetLink}'>Clique aqui para redefinir sua senha</a></p>";

            await _emailSender.SendEmailAsync(email, "Redefinição de Senha", html);
            return true;
        }

        public async Task<User?> ResetPasswordAsync(string token, string newPassword)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u =>
                u.PasswordResetToken == token && u.PasswordResetTokenExpiry > DateTime.UtcNow);

            if (user == null) return null;

            user.PasswordHash = HashPassword(newPassword);
            user.PasswordResetToken = null;
            user.PasswordResetTokenExpiry = null;

            await _context.SaveChangesAsync();
            return user;
        }

        public async Task<bool> SendTwoFactorCodeAsync(User user)
        {
            var code = new Random().Next(100000, 999999).ToString();
            user.TwoFactorCode = code;
            user.TwoFactorExpiry = DateTime.UtcNow.AddMinutes(5);
            user.IsTwoFactorVerified = false;
            await _context.SaveChangesAsync();

            var html = $"<p>Seu código de verificação 2FA é: <strong>{code}</strong></p>";
            await _emailSender.SendEmailAsync(user.Email, "Código de Verificação 2FA", html);

            return true;
        }

        public async Task<(string token, string refreshToken)?> ConfirmTwoFactorAsync(string login, string code, string ip, string device)
        {
            var user = await GetUserByLoginAsync(login);
            if (user == null || user.TwoFactorExpiry < DateTime.UtcNow)
                return null;

            if (user.TwoFactorAttempts >= 3)
            {
                user.TwoFactorCode = null;
                user.TwoFactorExpiry = null;
                user.TwoFactorAttempts = 0;
                await _context.SaveChangesAsync();
                return null;
            }

            if (user.TwoFactorCode != code)
            {
                user.TwoFactorAttempts++;
                await _context.SaveChangesAsync();
                return null;
            }

            var refreshToken = _tokenGenerator.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            user.IsTwoFactorVerified = true;
            user.TwoFactorCode = null;
            user.TwoFactorExpiry = null;
            user.TwoFactorAttempts = 0;
            await _context.SaveChangesAsync();

            var token = _tokenGenerator.GenerateToken(user);
            await RegisterSessionAsync(user, token, ip, device);

            return (token, refreshToken);
        }

        public async Task RegisterLoginAttemptAsync(string ip, bool success)
        {
            _context.LoginAttempts.Add(new LoginAttempt
            {
                IpAddress = ip,
                AttemptTime = DateTime.UtcNow,
                Success = success
            });

            await _context.SaveChangesAsync();
        }

        public async Task<bool> IsIpBlockedAsync(string ip)
        {
            var since = DateTime.UtcNow.AddMinutes(-10);
            var recentFails = await _context.LoginAttempts
                .Where(x => x.IpAddress == ip && !x.Success && x.AttemptTime >= since)
                .CountAsync();

            return recentFails >= 5;
        }

        public async Task RegisterSessionAsync(User user, string token, string ip, string device)
        {
            var session = new Session
            {
                UserId = user.Id,
                JwtToken = token,
                IpAddress = ip,
                Device = device,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };

            _context.Sessions.Add(session);
            await _context.SaveChangesAsync();
        }

        public async Task LogActivityAsync(int? userId, string ip, string action)
        {
            _context.ActivityLogs.Add(new ActivityLog
            {
                UserId = userId,
                IpAddress = ip,
                Action = action,
                Timestamp = DateTime.UtcNow
            });

            await _context.SaveChangesAsync();
        }

        public async Task RevokeTokenAsync(string token, DateTime expiresAt)
        {
            _context.RevokedTokens.Add(new RevokedToken
            {
                Token = token,
                RevokedAt = DateTime.UtcNow,
                ExpiresAt = expiresAt
            });

            await _context.SaveChangesAsync();
        }

        public async Task<User?> GetUserByLoginAsync(string login)
        {
            return await _context.Users.FirstOrDefaultAsync(u =>
                u.Username.ToLower() == login.ToLower() || u.Email == login.ToLower());
        }

        public async Task SaveChangesAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
