<?php
// Execute: php tests/reset-link.php (sem instalação do WordPress).
$source = file_get_contents(dirname(__DIR__) . '/zeropass-gvntrck.php');
function check($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}
$start = strpos($source, 'function pwless_rp_validate_token(');
$end = strpos($source, 'function pwless_process_reset_link_form_submission(', $start);
check($start !== false && $end !== false, 'Função ausente: pwless_rp_validate_token');
eval(substr($source, $start, $end - $start));

$options = array();
$meta = array();
function get_option($key, $default = false) { global $options; return $options[$key] ?? $default; }
function get_user_meta($user_id, $key, $single) { global $meta; return $meta[$user_id][$key] ?? ''; }
function wp_check_password($password, $hash) { return $hash === 'hash:' . $password; }
function get_user_by($field, $value) { $u = new stdClass(); $u->ID = $value; return $u; }

$meta[7]['pwless_rp_token'] = 'hash:secrettoken';
$meta[7]['pwless_rp_token_created'] = time();

check(pwless_rp_validate_token(7, 'secrettoken') instanceof stdClass, 'Token válido deve retornar o usuário');
check(pwless_rp_validate_token(7, 'errado') === false, 'Token errado deve falhar');
check(pwless_rp_validate_token(9, 'secrettoken') === false, 'Meta ausente deve falhar');
check(pwless_rp_validate_token(0, 'secrettoken') === false, 'User id inválido deve falhar');

$options['pwless_rp_link_expiry'] = 60;
$meta[7]['pwless_rp_token_created'] = time() - 3601;
check(pwless_rp_validate_token(7, 'secrettoken') === false, 'Token expirado deve falhar');

$meta[7]['pwless_rp_token_created'] = time() - 3599;
check(pwless_rp_validate_token(7, 'secrettoken') instanceof stdClass, 'Token dentro da validade deve passar');

unset($meta[7]['pwless_rp_token']);
check(pwless_rp_validate_token(7, 'secrettoken') === false, 'Meta removida (uso único) deve falhar');

echo "OK\n";
