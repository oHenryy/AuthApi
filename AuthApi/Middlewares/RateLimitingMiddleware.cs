using System.Collections.Concurrent;

namespace AuthApi.Middlewares
{
    public class RateLimitingMiddleware
    {
        private readonly RequestDelegate _next;
        private static readonly ConcurrentDictionary<string, List<DateTime>> _requests = new();

        private readonly int _limit = 5;         // Máx. requisições
        private readonly int _windowSeconds = 60; // Janela de tempo (segundos)

        public RateLimitingMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var path = context.Request.Path.Value ?? "/";
            var key = $"{ip}:{path}";

            var now = DateTime.UtcNow;
            var janela = now.AddSeconds(-_windowSeconds);

            var lista = _requests.GetOrAdd(key, _ => new List<DateTime>());
            lock (lista)
            {
                lista.RemoveAll(t => t < janela);
                if (lista.Count >= _limit)
                {
                    context.Response.StatusCode = 429;
                    context.Response.Headers["Retry-After"] = _windowSeconds.ToString();
                    context.Response.ContentType = "text/plain";
                    context.Response.WriteAsync("Muitas requisições. Tente novamente em instantes.");
                    return;
                }
                lista.Add(now);
            }

            await _next(context);
        }
    }
}
