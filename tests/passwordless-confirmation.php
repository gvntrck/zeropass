<?php
// Execute: php tests/passwordless-confirmation.php (sem instalação do WordPress).
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
    check($start !== false, 'Função ausente: ' . $name);
    $end = strpos($source, 'function ' . $next . '(', $start);
    check($end !== false, 'Fim da função ausente: ' . $name);
    eval(substr($source, $start, $end - $start));
}
define('MINUTE_IN_SECONDS', 60);
$home = 'https://example.test';
$options = array('permalink_structure' => '/%postname%/', 'pwless_link_expiry' => 60);
$meta = array();
$events = array();
$session_allowed = true;
function home_url($path) { global $home; return $home . $path; }
function get_option($key, $default = false) { global $options; return $options[$key] ?? $default; }
function wp_parse_url($url, $component) { return parse_url($url, $component); }
function wp_unslash($value) { return stripslashes($value); }
function sanitize_text_field($value) { return trim(strip_tags($value)); }
function sanitize_key($value) { return strtolower(preg_replace('/[^a-zA-Z0-9_\-]/', '', $value)); }
function absint($value) { return abs((int) $value); }
function is_admin() { return false; }
function get_user_by($field, $id) { return $id === 7 ? (object) array('ID' => 7, 'user_email' => 'user@example.test', 'user_login' => 'user') : false; }
function get_user_meta($id, $key, $single) { global $meta; return $meta[$key] ?? ''; }
function update_user_meta($id, $key, $value) { global $meta; $meta[$key] = $value; }
function delete_user_meta($id, $key) { global $meta; unset($meta[$key]); }
function wp_check_password($token, $hash) { return password_verify($token, $hash); }
function wp_verify_nonce($nonce, $action) { global $meta; return $nonce === 'valid' && $action === 'passwordless_login_7_' . ($meta['passwordless_login_token_created'] ?? ''); }
function pwless_log_attempt($email, $status) { global $events; $events[] = $status; }
function pwless_render_passwordless_login_page($args) { throw new RuntimeException('HTTP ' . $args['response_code']); }
function pwless_apply_loggedin_session_limit($id) { global $session_allowed; return array('allowed' => $session_allowed, 'message' => 'Limite de sessões'); }
function wp_set_current_user($id) { global $events; $events[] = 'current_user:' . $id; }
function wp_set_auth_cookie($id) { global $events; $events[] = 'cookie:' . $id; }
function do_action($action, $login, $user) { global $events; $events[] = $action; }
function pwless_force_login_tracking($id) { global $events; $events[] = 'tracking:' . $id; }
function pwless_get_redirect_after_login() { return 'https://example.test/destino'; }
function wp_safe_redirect($url) { global $events; $events[] = $url; throw new RuntimeException('redirect'); }
function fresh_token()
{
    global $meta, $events, $session_allowed;
    $meta = array('passwordless_login_token' => password_hash('secret', PASSWORD_DEFAULT), 'passwordless_login_token_created' => time());
    $events = array();
    $session_allowed = true;
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_POST = array('pwless_action' => 'confirm_passwordless_login', 'user' => 7, 'passwordless_login' => 'secret', 'nonce' => 'valid');
}
function process_request($expected)
{
    try {
        pwless_process_passwordless_login_confirmation_post();
        $actual = 'ignored';
    } catch (RuntimeException $error) {
        $actual = $error->getMessage();
    }
    check($actual === $expected, 'Resultado inesperado: ' . $actual . ', esperado: ' . $expected);
}
load_function('pwless_get_passwordless_confirmation_url', 'pwless_get_request_method');
load_function('pwless_get_request_method', 'pwless_render_passwordless_login_page');
load_function('pwless_mark_passwordless_token_as_used', 'pwless_validate_passwordless_login');
load_function('pwless_validate_passwordless_login', 'pwless_get_passwordless_confirmation_page_defaults');
load_function('pwless_process_passwordless_login_confirmation_post', 'pwless_process_passwordless_login');
check(strpos($source, '$form_action = pwless_get_passwordless_confirmation_url();') !== false, 'O formulário ainda envia para a raiz');
foreach (array('' => '/index.php/passwordless-confirmar/', '/%postname%/' => '/passwordless-confirmar/', '/index.php/%postname%/' => '/index.php/passwordless-confirmar/') as $structure => $path) {
    $options['permalink_structure'] = $structure;
    foreach (array('https://example.test', 'https://example.test/blog') as $home) {
        check(pwless_get_passwordless_confirmation_url() === $home . $path, 'URL incompatível com permalinks/subdiretório');
        $_SERVER['REQUEST_URI'] = parse_url($home . $path, PHP_URL_PATH) . '?extra=1';
        fresh_token();
        process_request('redirect');
        check($events === array('current_user:7', 'cookie:7', 'wp_login', 'tracking:7', 'login_sucesso', 'https://example.test/destino'), 'Fluxo de sessão/redirecionamento alterado');
        check(!pwless_validate_passwordless_login(7, 'secret', 'valid')['valid'], 'Token reutilizável');
        process_request('HTTP 403');
    }
}
$home = 'https://example.test';
$options['permalink_structure'] = '/%postname%/';
foreach (array('/', '/outra/', '/passwordless-confirmar/extra', '/blog/passwordless-confirmar/', '/index.php/passwordless-confirmar/') as $path) {
    fresh_token();
    $_SERVER['REQUEST_URI'] = $path;
    process_request('ignored');
    check($events === array(), 'Login aceito fora da rota');
}
$_SERVER['REQUEST_URI'] = '/passwordless-confirmar/';
foreach (array('GET', 'HEAD') as $method) {
    fresh_token();
    $_SERVER['REQUEST_METHOD'] = $method;
    process_request('ignored');
    check($events === array(), 'GET/HEAD autenticou usuário');
}
foreach (array('nonce', 'passwordless_login', 'user', 'expired', 'superseded', 'session', 'action') as $invalid) {
    fresh_token();
    if (in_array($invalid, array('nonce', 'passwordless_login', 'user'), true)) {
        $_POST[$invalid] = $invalid === 'user' ? 999 : 'invalid';
    } elseif ($invalid === 'expired') {
        $meta['passwordless_login_token_created'] = time() - 3600;
    } elseif ($invalid === 'superseded') {
        $meta['passwordless_login_previous_token'] = $meta['passwordless_login_token'];
    } elseif ($invalid === 'session') {
        $session_allowed = false;
    } else {
        unset($_POST['pwless_action']);
    }
    process_request($invalid === 'action' ? 'ignored' : 'HTTP 403');
    check(!in_array('cookie:7', $events, true), 'Autenticação não autorizada: ' . $invalid);
    check(isset($meta['passwordless_login_token']), 'Requisição inválida consumiu token');
}
echo "OK: rota, permalinks, subdiretórios, sessão, redirect, nonce, expiração e reutilização.\n";
