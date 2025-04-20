using Microsoft.AspNetCore.Mvc;
using AuthApi.Models;
using AuthApi.Services;
using AuthApi.Helpers;
using Microsoft.AspNetCore.Authorization;
using AuthApi.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly AuthService _authService;
        private readonly JwtTokenGenerator _tokenGenerator;

        public AuthController(AppDbContext context, AuthService authService, JwtTokenGenerator tokenGenerator)
        {
            _context = context;
            _authService = authService;
            _tokenGenerator = tokenGenerator;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var success = await _authService.RegisterAsync(model.Username, model.Email, model.Password);
            if (!success) return BadRequest("Usuário já existe.");
            return Ok("Usuário registrado com sucesso.");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            if (await _authService.IsIpBlockedAsync(ip))
                return StatusCode(429, "Muitas tentativas falhas. Tente novamente mais tarde.");

            var user = await _authService.AuthenticateAsync(model.Login, model.Password);

            await _authService.RegisterLoginAttemptAsync(ip, user != null);

            if (user == null)
                return Unauthorized("Credenciais inválidas.");

            await _authService.SendTwoFactorCodeAsync(user);
            await _authService.LogActivityAsync(user.Id, ip, "Login iniciado (2FA enviado)");
            return Ok("Código 2FA enviado. Confirme para receber o token.");
        }

        [HttpGet("profile")]
        [Authorize]
        public IActionResult GetProfile()
        {
            var username = HttpContext.User.Identity?.Name;
            return Ok(new { message = $"Bem-vindo, {username}!" });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenRequest request)
        {
            var result = await _authService.RefreshTokenAsync(request.Token, request.RefreshToken);
            if (result == null) return Unauthorized("Token inválido ou expirado.");

            return Ok(new { token = result.Value.token, refreshToken = result.Value.refreshToken });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var username = HttpContext.User?.Identity?.Name;
            if (username == null) return Unauthorized();

            var success = await _authService.RevokeRefreshTokenAsync(username);
            if (!success) return NotFound("Usuário não encontrado.");

            return Ok("Logout realizado com sucesso.");
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string token)
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var user = await _context.Users.FirstOrDefaultAsync(u => u.EmailVerificationToken == token);
            if (user == null) return BadRequest("Token inválido.");

            user.EmailConfirmed = true;
            user.EmailVerificationToken = null;
            await _context.SaveChangesAsync();

            await _authService.LogActivityAsync(user!.Id, ip, "Email confirmado");
            return Ok("E-mail confirmado com sucesso.");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel model)
        {
            var success = await _authService.RequestPasswordResetAsync(model.Email);
            if (!success) return NotFound("E-mail não encontrado.");
            return Ok("Link de redefinição enviado ao e-mail.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var user = await _authService.ResetPasswordAsync(model.Token, model.NewPassword);
            if (user == null)
                return BadRequest("Token inválido ou expirado.");

            await _authService.LogActivityAsync(user.Id, ip, "Senha redefinida");

            return Ok("Senha redefinida com sucesso.");
        }

        [HttpGet("reset-password")]
        public IActionResult ResetPasswordPage([FromQuery] string token)
        {
            return Ok($"Token recebido: {token}.");
        }

        [HttpPost("2fa/confirm")]
        public async Task<IActionResult> Confirm2FA([FromBody] TwoFactorModel model)
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var device = Request.Headers["User-Agent"].ToString();

            if (await _authService.IsIpBlockedAsync(ip))
                return StatusCode(429, "Muitas tentativas 2FA falharam. Tente mais tarde.");

            var tokenResult = await _authService.ConfirmTwoFactorAsync(
                model.Username,
                model.Code,
                ip,
                device
            );

            await _authService.RegisterLoginAttemptAsync(ip, tokenResult != null);

            if (tokenResult == null)
                return BadRequest("Código inválido ou expirado.");

            var user = await _authService.GetUserByLoginAsync(model.Username);
            if (user != null)
            {
                await _authService.RegisterSessionAsync(user, tokenResult.Value.token, ip, device);
                await _authService.LogActivityAsync(user!.Id, ip, "Verificação 2FA efetuada");
            }

            return Ok(new { tokenResult.Value.token, tokenResult.Value.refreshToken });
        }

        [HttpGet("sessions")]
        [Authorize]
        public async Task<IActionResult> GetSessions()
        {
            var userId = int.Parse(User.Claims.First(c => c.Type == "userId").Value);

            var sessions = await _context.Sessions
                .Where(s => s.UserId == userId)
                .Select(s => new
                {
                    s.Id,
                    s.IpAddress,
                    s.Device,
                    s.CreatedAt,
                    s.ExpiresAt
                })
                .ToListAsync();

            return Ok(sessions);
        }

        [HttpDelete("sessions/{id}")]
        [Authorize]
        public async Task<IActionResult> DeleteSession(int id)
        {
            var userId = int.Parse(User.Claims.First(c => c.Type == "userId").Value);

            var session = await _context.Sessions.FirstOrDefaultAsync(s => s.Id == id && s.UserId == userId);
            if (session == null) return NotFound("Sessão não encontrada.");

            _context.Sessions.Remove(session);
            await _context.SaveChangesAsync();

            return Ok("Sessão encerrada.");
        }
    }
}
