<?php
// Execute: php tests/front-language.php (sem instalação do WordPress).
$source = file_get_contents(dirname(__DIR__) . '/zeropass-gvntrck.php');
function check($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}
function load_function($name, $next)
{
    global $source;
    $start = strpos($source, 'function ' . $name . '(');
    $end = strpos($source, 'function ' . $next . '(', $start);
    check($start !== false && $end !== false, 'Função ausente: ' . $name);
    eval(substr($source, $start, $end - $start));
}
function add_shortcode($name, $callback) {}
function add_action($name, $callback) {}
function get_locale() { global $locale; return $locale; }
function get_option($name, $default = false) { global $options; return $options[$name] ?? $default; }
function is_user_logged_in() { global $logged_in; return $logged_in; }
function esc_html($value) { return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8'); }
function esc_attr($value) { return esc_html($value); }
function esc_url($value) { return $value; }
function wp_kses_post($value) { return $value; }
function wp_nonce_field($action, $name) {}
function pwless_get_login_form_redirect_url() { return '/login'; }
function admin_url($path) { return '/wp-admin/' . $path; }
function plugins_url($path, $file) { return '/plugin/' . $path; }
function wp_unique_id($prefix) { return $prefix . '1'; }
function wp_create_nonce($action) { return 'nonce'; }
function wp_json_encode($value) { return json_encode($value); }
function check_ajax_referer($action, $name) {}
function wp_unslash($value) { return $value; }
function wp_send_json_error($data) { throw new RuntimeException($data['message']); }
function pwless_rp_validate_token($user_id, $token) { return $user_id === 7 && $token === 'valid'; }
function sanitize_text_field($value) { return $value; }
function absint($value) { return abs((int) $value); }

load_function('pwless_front_text', 'pwless_get_login_form_redirect_url');
load_function('display_login_form', 'pwless_reset_password_form');
load_function('pwless_get_password_requirements', 'pwless_get_password_errors');
load_function('pwless_get_password_errors', 'pwless_change_password_form');
load_function('pwless_change_password_form', 'pwless_ajax_change_password');
load_function('pwless_ajax_change_password', 'pwless_sync_logged_in_cookie');
load_function('pwless_reset_link_form', 'pwless_get_redirect_after_login');
load_function('pwless_get_passwordless_confirmation_page_defaults', 'pwless_get_passwordless_confirmation_url');

$_SERVER['REQUEST_METHOD'] = 'GET';
$options = array();
$logged_in = false;
$locale = 'pt_BR';
check(strpos(display_login_form(), 'Digite seu email:') !== false, 'Formulário em português');
check(strpos(pwless_reset_link_form(), 'Enviar link de redefinição') !== false, 'Reset em português');
check(pwless_get_password_errors('123') === array('Mínimo de 8 caracteres'), 'Requisitos em português');

foreach (array('en_US', 'en_GB') as $locale) {
    check(strpos(display_login_form(), 'Enter your email:') !== false, 'Formulário em inglês');
    check(strpos(pwless_reset_link_form(), 'Send reset link') !== false, 'Reset em inglês');
    $logged_in = true;
    check(strpos(pwless_change_password_form(), 'Confirm new password') !== false, 'Alteração de senha em inglês');
    $logged_in = false;
    check(pwless_get_password_errors('123') === array('At least 8 characters'), 'Requisitos em inglês');
    check(pwless_get_passwordless_confirmation_page_settings()['title'] === 'Confirm login', 'Confirmação em inglês');
    check(pwless_front_text('Seu link de login') === 'Your login link', 'Assunto padrão em inglês');
    check(strpos(pwless_front_text('<a href="{reset_url}">Clique aqui para definir uma nova senha</a><br><br>O link tem validade de {expiry_time} minuto(s).'), '{reset_url}') !== false, 'Preserva variáveis do e-mail');
    $_GET = array('pwless_rp' => 'valid', 'pwless_rp_user' => 7);
    check(strpos(pwless_reset_link_form(), 'Save new password') !== false, 'Formulário do link em inglês');
    $_GET = array();
    $_POST = array('new_password' => 'one', 'confirm_password' => 'two');
    try {
        pwless_ajax_change_password();
        check(false, 'AJAX deveria rejeitar senhas diferentes');
    } catch (RuntimeException $error) {
        check($error->getMessage() === 'Passwords do not match.', 'Erro AJAX em inglês');
    }
}
$options['pwless_form_button_text'] = 'Texto personalizado';
$options['pwless_confirmation_page_title'] = 'Título personalizado';
check(strpos(display_login_form(), 'Texto personalizado') !== false, 'Preserva botão personalizado');
check(pwless_get_passwordless_confirmation_page_settings()['title'] === 'Título personalizado', 'Preserva confirmação personalizada');
check(pwless_front_text('Meu e-mail personalizado') === 'Meu e-mail personalizado', 'Preserva e-mail personalizado');
$locale = 'es_ES';
check(pwless_front_text('Enviar link') === 'Enviar link', 'Outros idiomas mantêm português');
echo "OK: idiomas, formulários, requisitos e personalizações.\n";
