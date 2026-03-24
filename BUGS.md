# 🐛 Relatório de Bugs — ZeroPass Login v4.1.5

**Arquivo:** `zeropass-gvntrck.php`
**Data:** 25/02/2026



## 🟡 Bug 5 — SQL sem `$wpdb->prepare()` na consulta de logs

**Severidade:** Média
**Linhas:** 1173–1174
**Função:** `pwless_settings_page()` (aba Logs)

**Problema:**
A variável `$table_name` é interpolada diretamente nas queries SQL. Embora `$wpdb->prefix` seja considerado seguro, a prática recomendada é usar `$wpdb->prepare()`.

**Código atual:**
```php
$wpdb->get_var("SHOW TABLES LIKE '$table_name'")
$wpdb->get_results("SELECT * FROM $table_name ORDER BY created_at DESC LIMIT 10")
```

**Correção sugerida:**
```php
$wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name))
$wpdb->get_results(
    $wpdb->prepare("SELECT * FROM `{$table_name}` ORDER BY created_at DESC LIMIT %d", 10)
)
```

> **Nota:** O mesmo problema existe em `pwless_create_log_table()` (linha 1301).

---

## 🟡 Bug 6 — Input não sanitizado antes do log de reCAPTCHA

**Severidade:** Média
**Linhas:** 91, 98
**Função:** `passwordless_login_form()`

**Problema:**
Quando o reCAPTCHA falha, o email do usuário é passado para `pwless_log_attempt()` usando `$_POST['user_email']` diretamente, **antes** de ser sanitizado (a sanitização com `sanitize_email()` só ocorre na linha 103).

**Código atual:**
```php
pwless_log_attempt($_POST['user_email'], 'Falha - Captcha inválido');  // linha 91
pwless_log_attempt($_POST['user_email'], 'Falha - Captcha falhou');    // linha 98
```

**Correção sugerida:**
```php
pwless_log_attempt(sanitize_email($_POST['user_email']), 'Falha - Captcha inválido');
pwless_log_attempt(sanitize_email($_POST['user_email']), 'Falha - Captcha falhou');
```

---

## 🟡 Bug 7 — Conflito de IDs HTML `countdown`

**Severidade:** Média
**Linhas:** 55 e 291

**Problema:**
As funções `passwordless_login_form()` e `pwless_reset_password_form()` ambas usam `id="countdown"` no span do timer de redirecionamento. Se os dois shortcodes forem usados na mesma página, apenas o primeiro elemento será encontrado pelo `document.getElementById()`.

**Código atual (em ambas as funções):**
```html
<span id="countdown">5</span>
```
```javascript
var countdown = document.getElementById('countdown');
```

**Correção sugerida:**
Usar IDs únicos para cada shortcode:

Na `passwordless_login_form()`:
```html
<span id="pwless-login-countdown">5</span>
```
```javascript
var countdown = document.getElementById('pwless-login-countdown');
```

Na `pwless_reset_password_form()`:
```html
<span id="pwless-reset-countdown">5</span>
```
```javascript
var countdown = document.getElementById('pwless-reset-countdown');
```

---

## 🟢 Bug 8 — Inconsistência `time()` vs `current_time('timestamp')`

**Severidade:** Baixa
**Linhas:** 112, 830 vs 471, 779

**Problema:**
O login passwordless (via email) usa `time()` (UTC) para criar e verificar tokens, enquanto o login via admin link usa `current_time('timestamp')` (timezone do WordPress). Isso causa inconsistência no codebase.

**Código no login por email:**
```php
$token_created = time();                            // linha 112 — criação
$token_age = time() - intval($token_created);       // linha 830 — verificação
```

**Código no admin link:**
```php
$created_at = current_time('timestamp');             // linha 471 — criação
$now = current_time('timestamp');                    // linha 779 — verificação
```

**Correção sugerida:**
Padronizar ambas as abordagens. Como `time()` (UTC) é mais seguro contra mudanças de timezone, a melhor prática é usar `time()` em ambos e reservar `current_time()` apenas para exibição:

```php
// Na função de admin link (linhas 471 e 779), trocar para:
$created_at = time();
$now = time();
```

> **Nota:** Se optar por `current_time('timestamp')`, certifique-se de usar em **todas** as funções.
