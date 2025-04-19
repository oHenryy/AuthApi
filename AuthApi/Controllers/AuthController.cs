using Microsoft.AspNetCore.Mvc;
using AuthApi.Models;
using AuthApi.Services;
using AuthApi.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly JwtTokenGenerator _tokenGenerator;

        public AuthController(AuthService authService, JwtTokenGenerator tokenGenerator)
        {
            _authService = authService;
            _tokenGenerator = tokenGenerator;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var success = await _authService.RegisterAsync(model.Username, model.Password);
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
    }
}
