# 🔐 AuthApi – API de Autenticação em ASP.NET Core

Esse é um projeto simples, uma API de autenticação com suporte a login com 2FA, JWT, refresh token, sessões, rate limiting, administração e algumas outras funcionalidades.

---

## ✅ Funcionalidades

- Registro com confirmação de e-mail
- Login com **username ou e-mail** (case-insensitive)
- Autenticação em dois fatores (2FA via e-mail)
- JWT + Refresh Token com reemissão automática
- Recuperação de senha via link por e-mail
- Controle e revogação de sessões por dispositivo
- Logout individual e global
- Lista de revogação de tokens JWT
- Bloqueio de IP por tentativas falhas
- Rate limiting global (IP + rota)
- Logs de atividades por usuário
- Painel Admin com controle de usuários e sessões
- Limpeza automática de sessões e tokens expirados

---

## 🚀 Tecnologias

- ASP.NET Core 8
- Entity Framework Core (InMemory)
- JWT (System.IdentityModel.Tokens.Jwt)
- Mailtrap (SMTP)
- Swagger (Swashbuckle)
- Background Services (Hosted Services)

---

## ⚙️ Configuração

### `appsettings.json`

```json
{
  "Jwt": {
    "Key": "chave_segura_maior_que_32_caracteres",
    "Issuer": "AuthApi",
    "Audience": "AuthApiUsers"
  },
  "Smtp": {
    "Host": "smtp.mailtrap.io",
    "Port": 2525,
    "Username": "SEU_USER_MAILTRAP",
    "Password": "SUA_SENHA_MAILTRAP",
    "From": "no-reply@authapi.com"
  },
  "AllowedHosts": "*"
}
```

---

## 🧪 Fluxo de uso

1. **Registro:**
   - `POST /auth/register`
   - Confirma e-mail via `/auth/confirm-email?token=...`

2. **Login:**
   - `POST /auth/login`
   - Recebe código 2FA por e-mail
   - Confirma com `POST /auth/2fa/confirm` → retorna JWT + RefreshToken

3. **Autenticado:**
   - Enviar JWT no header `Authorization: Bearer ...`
   - Acessar rotas protegidas

4. **Refresh de Token:**
   - `POST /auth/refresh` com o par antigo

5. **Recuperação de Senha:**
   - `POST /auth/forgot-password`
   - `POST /auth/reset-password`

6. **Sessões:**
   - `GET /auth/sessions`
   - `DELETE /auth/sessions/{id}`

7. **Logout:**
   - `POST /auth/logout` → revoga token e refresh

---

## 🔐 Endpoints protegidos por ROLE

### `admin`

| Método | Rota                              | Descrição                     |
|--------|-----------------------------------|-------------------------------|
| GET    | `/admin/users`                    | Lista todos os usuários       |
| GET    | `/admin/sessions`                 | Lista todas as sessões        |
| GET    | `/admin/users/{id}/sessions`      | Sessões de um usuário         |
| GET    | `/admin/logs`                     | Logs de atividades do sistema |

---

## 👤 Admin padrão

Há um usuário admin predefinido no `Program.cs`:

```csharp
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    if (!db.Users.Any(u => u.Username == "admin"))
    {
        db.Users.Add(new User
        {
            Username = "admin",
            Email = "admin@authapi.com",
            PasswordHash = AuthService.HashPassword("Admin123!"),
            EmailConfirmed = true,
            Role = "admin"
        });
        await db.SaveChangesAsync();
    }
}
```

---

## 🧼 Limpeza automática

Rodando via `BackgroundService`, a cada 10 min:

- Remove sessões expiradas
- Remove tokens JWT revogados vencidos