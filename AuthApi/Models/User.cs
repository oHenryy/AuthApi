namespace AuthApi.Models
{
    public class User
    {
        public int Id { get; set; }
        public required string Username { get; set; }
        public required string PasswordHash { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime {  get; set; }
        public string Role { get; set; } = "user";
    }
}
