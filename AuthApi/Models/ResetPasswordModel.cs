namespace AuthApi.Models
{
    public class ResetPasswordModel
    {
        public string Token { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
}
