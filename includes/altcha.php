<?php

function pwless_altcha_generate_challenge()
{
    $hmac_key = get_option('pwless_altcha_hmac_key', '');
    if (empty($hmac_key)) {
        wp_send_json_error(array('error' => 'ALTCHA não configurado.'));
    }

    $max_number = intval(get_option('pwless_altcha_complexity', 50000));
    if ($max_number < 1000) {
        $max_number = 50000;
    }

    $salt = bin2hex(random_bytes(12));
    $secret_number = random_int(0, $max_number);
    $algorithm = 'SHA-256';

    $challenge = hash('sha256', $salt . $secret_number);
    $signature = hash_hmac('sha256', $challenge, $hmac_key);

    wp_send_json(array(
        'algorithm' => $algorithm,
        'challenge' => $challenge,
        'maxnumber' => $max_number,
        'salt' => $salt,
        'signature' => $signature,
    ));
}
add_action('wp_ajax_pwless_altcha_challenge', 'pwless_altcha_generate_challenge');
add_action('wp_ajax_nopriv_pwless_altcha_challenge', 'pwless_altcha_generate_challenge');

function pwless_altcha_verify($payload_base64)
{
    $hmac_key = get_option('pwless_altcha_hmac_key', '');
    if (empty($hmac_key) || empty($payload_base64)) {
        return false;
    }

    $payload = json_decode(base64_decode($payload_base64), true);
    if (!is_array($payload) || !isset($payload['algorithm'], $payload['challenge'], $payload['number'], $payload['salt'], $payload['signature'])) {
        return false;
    }

    $expected_challenge = hash('sha256', $payload['salt'] . $payload['number']);
    if (!hash_equals($expected_challenge, $payload['challenge'])) {
        return false;
    }

    $expected_signature = hash_hmac('sha256', $payload['challenge'], $hmac_key);
    if (!hash_equals($expected_signature, $payload['signature'])) {
        return false;
    }

    return true;
}
