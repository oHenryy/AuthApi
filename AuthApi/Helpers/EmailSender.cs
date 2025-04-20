using System.Net;
using System.Net.Mail;

namespace AuthApi.Helpers
{
    public class EmailSender
    {
        private readonly IConfiguration _config;

        public EmailSender(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            var smtp = _config.GetSection("Smtp");
            var from = smtp["From"];

            if (string.IsNullOrWhiteSpace(from))
                throw new InvalidOperationException("O campo 'Smtp:From' está ausente ou vazio no appsettings.json.");

            var client = new SmtpClient(smtp["Host"], int.Parse(smtp["Port"]!))
            {
                Credentials = new NetworkCredential(smtp["Username"], smtp["Password"]),
                EnableSsl = true
            };

            var message = new MailMessage(from, to, subject, body)
            {
                IsBodyHtml = true
            };

            await client.SendMailAsync(message);
        }
    }
}
