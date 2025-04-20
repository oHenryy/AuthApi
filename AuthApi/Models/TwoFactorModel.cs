namespace AuthApi.Models
{
    public class TwoFactorModel
    {
        public string Username { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
    }
}
