using System.Security.Cryptography;
using System.Text;
using AuthApi.Models;
using AuthApi.Data;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using AuthApi.Helpers;

namespace AuthApi.Services
{
    public class AuthService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _config;
        private readonly JwtTokenGenerator _tokenGenerator;

        public AuthService(AppDbContext context, IConfiguration config, JwtTokenGenerator tokenGenerator)
        {
            _context = context;
            _config = config;
            _tokenGenerator = tokenGenerator;
        }

        public async Task<bool> RegisterAsync(string username, string password)
        {
            if (await _context.Users.AnyAsync(u => u.Username == username))
                return false;

            var passwordHash = HashPassword(password);

            var role = username == "admin" ? "admin" : "user";
            var user = new User { Username = username, PasswordHash = passwordHash, Role = role };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<User?> AuthenticateAsync(string username, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
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

        public async Task<(string token, string refreshToken)?> RefreshTokenAsync(string token, string refreshToken)
        {
            var principal = GetPrincipalFromExpiredToken(token);
            var username = principal?.Identity?.Name;

            if (username == null) return null;

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                return null;

            var newToken = _tokenGenerator.GenerateToken(user);
            var newRefreshToken = _tokenGenerator.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _context.SaveChangesAsync();

            return (newToken, newRefreshToken);
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = _config["Jwt:Issuer"],
                ValidAudience = _config["Jwt:Audience"],
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToen);

            if (securityToen is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                return null;

            return principal;
        }

        public async Task<bool> RevokeRefreshTokenAsync(string username)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null) return false;

            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;

            await _context.SaveChangesAsync();
            return true;
        }

        public async Task SaveChangesAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
