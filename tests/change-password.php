<?php
// Execute: php tests/change-password.php (sem instalação do WordPress).
$source = file_get_contents(dirname(__DIR__) . '/zeropass-gvntrck.php');
function check($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}
foreach (array('pwless_get_password_requirements' => 'pwless_get_password_errors', 'pwless_get_password_errors' => 'pwless_change_password_form') as $name => $next) {
    $start = strpos($source, 'function ' . $name . '(');
    $end = strpos($source, 'function ' . $next . '(', $start);
    check($start !== false && $end !== false, 'Função ausente: ' . $name);
    eval(substr($source, $start, $end - $start));
}
function pwless_front_text($text) { return $text; }
$options = array();
function get_option($key, $default = false) { global $options; return $options[$key] ?? $default; }

check(pwless_get_password_errors('1234567') === array('Mínimo de 8 caracteres'), 'Padrão deve exigir 8 caracteres');
check(pwless_get_password_errors('12345678') === array(), 'Padrão deve aceitar 8 caracteres');

$options = array('pwless_pw_min_length' => 4, 'pwless_pw_require_upper' => true, 'pwless_pw_require_lower' => true, 'pwless_pw_require_number' => true, 'pwless_pw_require_special' => true);
check(count(pwless_get_password_errors('abc')) === 4, 'Deve falhar em tamanho, maiúscula, número e especial');
check(pwless_get_password_errors('Ação1!') === array(), 'Deve aceitar senha que cumpre tudo (com acentos)');
check(pwless_get_password_errors('ÁÇÃO1!') === array('Ao menos uma letra minúscula'), 'Deve exigir minúscula');

echo "OK\n";
