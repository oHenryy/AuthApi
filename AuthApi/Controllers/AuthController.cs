using Microsoft.AspNetCore.Mvc;
using AuthApi.Models;
using AuthApi.Services;
using AuthApi.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
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

        public AuthController(AppDbContext context,AuthService authService, JwtTokenGenerator tokenGenerator)
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
            var user = await _authService.AuthenticateAsync(model.Username, model.Password);
            if (user == null) return Unauthorized("Credenciais inválidas.");

            var token = _tokenGenerator.GenerateToken(user);
            var refreshToken = _tokenGenerator.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _authService.SaveChangesAsync();

            return Ok(new { token, refreshToken });
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

        [HttpGet("admin-area")]
        [Authorize(Roles = "admin")]
        public IActionResult AdminOnly()
        {
            return Ok("Acesso liberado para admin.");
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string token)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.EmailVerificationToken == token);
            if (user == null) return BadRequest("Token inválido.");

            user.EmailConfirmed = true;
            user.EmailVerificationToken = null;
            await _context.SaveChangesAsync();

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
            var success = await _authService.ResetPasswordAsync(model.Token, model.NewPassword);
            if (!success) return BadRequest("Token inválido ou expirado.");
            return Ok("Senha redefinida com sucesso.");
        }

        [HttpGet("reset-password")]
        public IActionResult ResetPasswordPage([FromQuery] string token)
        {
            return Ok($"Token recebido: {token}.");
        }
    }
}
