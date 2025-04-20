namespace AuthApi.Models
{
    public class Session
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public User User { get; set; } = null!;
        public string JwtToken { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string Device { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
    }
}
