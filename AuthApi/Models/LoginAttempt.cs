namespace AuthApi.Models
{
    public class LoginAttempt
    {
        public int Id { get; set; }
        public string IpAddress { get; set; } = string.Empty;
        public DateTime AttemptTime { get; set; }
        public bool Success { get; set; }
    }
}
