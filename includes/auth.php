<?php

function pwless_get_redirect_after_login()
{
    $redirect_url = get_option('pwless_redirect_url');
    if (empty($redirect_url)) {
        $redirect_url = home_url();
    }

    return $redirect_url;
}

function pwless_user_can_login_with_loggedin_plugin($user_id)
{
    if (!class_exists('Loggedin')) {
        return true;
    }

    $loggedin = new Loggedin();
    $check = $loggedin->validate_block_logic(true, '', '', $user_id);

    return $check !== false;
}

function pwless_force_login_tracking($user_id)
{
    if (!$user_id) {
        return;
    }

    $login_data = array(
        'ip' => isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '',
        'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
        'time' => current_time('timestamp'),
    );

    $history = get_user_meta($user_id, '_login_history', true);
    if (!is_array($history)) {
        $history = array();
    }

    array_unshift($history, $login_data);
    $history = array_slice($history, 0, 50);

    update_user_meta($user_id, '_login_history', $history);
    update_user_meta($user_id, 'last_login', current_time('mysql'));
}

function pwless_track_superseded_passwordless_token($user_id)
{
    $active_token = get_user_meta($user_id, 'passwordless_login_token', true);

    if (empty($active_token)) {
        delete_user_meta($user_id, 'passwordless_login_previous_token');
        return;
    }

    update_user_meta($user_id, 'passwordless_login_previous_token', $active_token);
}

function pwless_mark_passwordless_token_as_used($user_id)
{
    $active_token = get_user_meta($user_id, 'passwordless_login_token', true);

    if (!empty($active_token)) {
        update_user_meta($user_id, 'passwordless_login_last_used_token', $active_token);
    }

    delete_user_meta($user_id, 'passwordless_login_token');
    delete_user_meta($user_id, 'passwordless_login_token_created');
    delete_user_meta($user_id, 'passwordless_login_previous_token');
}

function pwless_validate_passwordless_login($user_id, $token, $nonce)
{
    $result = array(
        'valid' => false,
        'user' => null,
        'log_status' => 'Link inválido',
        'message' => 'Link inválido. Solicite um novo link de acesso.',
    );

    if ($user_id <= 0) {
        $result['log_status'] = 'Link inválido: usuário inválido';
        $result['message'] = 'Link inválido: usuário não identificado.';
        return $result;
    }

    $user = get_user_by('ID', $user_id);
    if (!$user) {
        $result['log_status'] = 'Link inválido: usuário não encontrado';
        $result['message'] = 'Link inválido: usuário não encontrado.';
        return $result;
    }

    $result['user'] = $user;

    if ($token === '') {
        $result['log_status'] = 'Link inválido: token ausente';
        $result['message'] = 'Link inválido: token de acesso ausente.';
        return $result;
    }

    if ($nonce === '') {
        $result['log_status'] = 'Link inválido: nonce ausente';
        $result['message'] = 'Link inválido: assinatura de segurança ausente.';
        return $result;
    }

    $saved_token = get_user_meta($user_id, 'passwordless_login_token', true);
    $token_created = intval(get_user_meta($user_id, 'passwordless_login_token_created', true));
    $previous_token = get_user_meta($user_id, 'passwordless_login_previous_token', true);
    $last_used_token = get_user_meta($user_id, 'passwordless_login_last_used_token', true);

    if (!empty($last_used_token) && wp_check_password($token, $last_used_token)) {
        $result['log_status'] = 'Link já utilizado';
        $result['message'] = 'Este link já foi utilizado. Solicite um novo link de acesso.';
        return $result;
    }

    if (!empty($previous_token) && wp_check_password($token, $previous_token)) {
        $result['log_status'] = 'Link antigo: existe link mais recente';
        $result['message'] = 'Este link é antigo e já existe um link mais recente para este usuário. Utilize o link mais recente ou solicite outro link de acesso.';
        return $result;
    }

    if (empty($saved_token)) {
        $result['log_status'] = 'Link inválido: sem token ativo';
        $result['message'] = 'Este link não é mais válido porque não existe um token ativo para este usuário.';
        return $result;
    }

    if ($token_created <= 0) {
        $result['log_status'] = 'Link inválido: sem data do token';
        $result['message'] = 'Link inválido: data de criação do token ausente ou inválida.';
        return $result;
    }

    if (!wp_verify_nonce($nonce, 'passwordless_login_' . $user_id . '_' . $token_created)) {
        $result['log_status'] = 'Link inválido: nonce inválido';
        $result['message'] = 'Link inválido: assinatura de segurança inválida.';
        return $result;
    }

    if (!wp_check_password($token, $saved_token)) {
        $result['log_status'] = 'Link inválido: token divergente';
        $result['message'] = 'Este link não corresponde ao token mais recente gerado para este usuário.';
        return $result;
    }

    $token_age = time() - $token_created;
    if ($token_age < 0) {
        $result['log_status'] = 'Link inválido: data do token inválida';
        $result['message'] = 'Link inválido: a data de criação do token é inválida.';
        return $result;
    }

    $expiry_seconds = max(1, intval(get_option('pwless_link_expiry', 60))) * MINUTE_IN_SECONDS;
    if ($token_age >= $expiry_seconds) {
        $result['log_status'] = 'Link expirado';
        $result['message'] = 'Link expirado. Por favor, solicite um novo link de acesso.';
        return $result;
    }

    $result['valid'] = true;
    return $result;
}

function pwless_process_passwordless_login_legacy()
{
    if (isset($_GET['passwordless_login']) && isset($_GET['user']) && isset($_GET['nonce'])) {
        $user_id = intval($_GET['user']);
        $token = sanitize_text_field(wp_unslash($_GET['passwordless_login']));
        $nonce = sanitize_text_field(wp_unslash($_GET['nonce']));
        $validation = pwless_validate_passwordless_login($user_id, $token, $nonce);
        if (!$validation['valid']) {
            $user = $validation['user'];

            pwless_log_attempt($user ? $user->user_email : 'unknown', $validation['log_status']);
            echo '<p class="error">' . esc_html($validation['message']) . '</p>';
            return;
        }
        $user = $validation['user'];

        if (!pwless_user_can_login_with_loggedin_plugin($user_id)) {
            echo '<p class="error">Você atingiu o limite máximo de logins simultâneos. Por favor, aguarde as sessões antigas expirarem ou faça logout em outro dispositivo.</p>';
            return;
        }

        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id);

        if ($user) {
            do_action('wp_login', $user->user_login, $user);
        }

        pwless_force_login_tracking($user_id);

        delete_user_meta($user_id, 'passwordless_login_token');
        delete_user_meta($user_id, 'passwordless_login_token_created');

        pwless_log_attempt($user ? $user->user_email : 'unknown', 'login_sucesso');

        wp_safe_redirect(pwless_get_redirect_after_login());
        exit;

        echo '<p class="error">Link inválido ou expirado. Por favor, solicite um novo link de acesso.</p>';
    }
}

function pwless_process_passwordless_login()
{
    if (!isset($_GET['passwordless_login']) || !isset($_GET['user']) || !isset($_GET['nonce'])) {
        return;
    }

    $user_id = intval($_GET['user']);
    $token = sanitize_text_field(wp_unslash($_GET['passwordless_login']));
    $nonce = sanitize_text_field(wp_unslash($_GET['nonce']));
    $validation = pwless_validate_passwordless_login($user_id, $token, $nonce);

    if (!$validation['valid']) {
        $user = $validation['user'];
        pwless_log_attempt($user ? $user->user_email : 'unknown', $validation['log_status']);
        echo '<p class="error">' . esc_html($validation['message']) . '</p>';
        return;
    }

    $user = $validation['user'];

    if (!pwless_user_can_login_with_loggedin_plugin($user_id)) {
        echo '<p class="error">Você atingiu o limite máximo de logins simultâneos. Por favor, aguarde as sessões antigas expirarem ou faça logout em outro dispositivo.</p>';
        return;
    }

    wp_set_current_user($user_id);
    wp_set_auth_cookie($user_id);

    if ($user) {
        do_action('wp_login', $user->user_login, $user);
    }

    pwless_force_login_tracking($user_id);

    pwless_mark_passwordless_token_as_used($user_id);

    pwless_log_attempt($user ? $user->user_email : 'unknown', 'login_sucesso');

    wp_safe_redirect(pwless_get_redirect_after_login());
    exit;
}

function process_passwordless_login()
{
    return pwless_process_passwordless_login();
}
add_action('init', 'pwless_process_passwordless_login');
