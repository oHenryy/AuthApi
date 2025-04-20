namespace AuthApi.Models
{
    public class User
    {
        public int Id { get; set; }
        public required string Username { get; set; }
        public required string Email { get; set; }
        public required string PasswordHash { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime {  get; set; }
        public string Role { get; set; } = "user";
        public bool EmailConfirmed { get; set; } = false;
        public string? EmailVerificationToken { get; set; }
        public string? PasswordResetToken { get; set; }
        public DateTime? PasswordResetTokenExpiry { get; set; }
        public string? TwoFactorCode { get; set; }
        public DateTime? TwoFactorExpiry { get; set; }
        public bool IsTwoFactorVerified { get; set; } = false;
        public int TwoFactorAttempts { get; set; } = 0;
    }
}
