<?php
/*
Plugin Name: ZeroPass Login
Plugin URI: https://github.com/gvntrck/zeropass
Description: Login sem complicações. Com o ZeroPass Login, seus usuários acessam sua plataforma com links seguros enviados por e-mail. Sem senhas, sem estresse – apenas segurança e simplicidade.
Version: 4.2.4
Author: Giovani Tureck - gvntrck
Author URI: https://projetoalfa.org
License: GPL v2 or later
Text Domain: zeropass-login
*/



require 'plugin-update-checker/plugin-update-checker.php';
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

$myUpdateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/gvntrck/zeropass/',
    __FILE__,
    'zeropass-gvntrck'
);

//Set the branch that contains the stable release.
$myUpdateChecker->setBranch('main');

//Optional: If you're using a private repository, specify the access token like this:
$myUpdateChecker->setAuthentication('your-token-here');



if (!defined('PWLESS_PLUGIN_VERSION')) {
    define('PWLESS_PLUGIN_VERSION', '4.2.4');
}

function pwless_get_login_form_redirect_url($args = array())
{
    $redirect_url = remove_query_arg(array('pwless_notice'));

    if (!empty($args)) {
        $redirect_url = add_query_arg($args, $redirect_url);
    }

    return $redirect_url;
}

function pwless_store_login_form_feedback($message, $email = '')
{
    $feedback_key = wp_generate_uuid4();
    $feedback_data = array(
        'message' => $message,
        'email' => sanitize_email($email),
    );

    set_transient(
        'pwless_login_feedback_' . $feedback_key,
        $feedback_data,
        5 * MINUTE_IN_SECONDS
    );

    return $feedback_key;
}

function pwless_get_login_form_feedback()
{
    if (!isset($_GET['pwless_notice'])) {
        return array(
            'message' => '',
            'email' => '',
        );
    }

    $feedback_key = sanitize_key(wp_unslash($_GET['pwless_notice']));
    if ($feedback_key === '') {
        return array(
            'message' => '',
            'email' => '',
        );
    }

    $feedback_data = get_transient('pwless_login_feedback_' . $feedback_key);
    if (!is_array($feedback_data)) {
        return array(
            'message' => '',
            'email' => '',
        );
    }

    return array(
        'message' => isset($feedback_data['message']) ? $feedback_data['message'] : '',
        'email' => isset($feedback_data['email']) ? sanitize_email($feedback_data['email']) : '',
    );
}

function pwless_redirect_login_form_with_feedback($message, $email = '')
{
    $feedback_key = pwless_store_login_form_feedback($message, $email);
    $redirect_url = pwless_get_login_form_redirect_url(array(
        'pwless_notice' => $feedback_key,
    ));

    wp_safe_redirect($redirect_url);
    exit;
}

function pwless_get_html_mail_content_type()
{
    return 'text/html';
}

function pwless_get_html_mail_charset()
{
    return 'UTF-8';
}

function pwless_prepare_email_content($content)
{
    $content = trim((string) $content);

    if ($content === '') {
        return '';
    }

    return wpautop($content);
}

function pwless_send_html_mail($to, $subject, $content)
{
    add_filter('wp_mail_content_type', 'pwless_get_html_mail_content_type');
    add_filter('wp_mail_charset', 'pwless_get_html_mail_charset');

    $sent = wp_mail($to, $subject, pwless_prepare_email_content($content));

    remove_filter('wp_mail_content_type', 'pwless_get_html_mail_content_type');
    remove_filter('wp_mail_charset', 'pwless_get_html_mail_charset');

    return $sent;
}

function pwless_handle_passwordless_login_form_submission()
{
    if (is_admin()) {
        return;
    }

    if (!isset($_SERVER['REQUEST_METHOD']) || strtoupper(wp_unslash($_SERVER['REQUEST_METHOD'])) !== 'POST') {
        return;
    }

    if (!isset($_POST['pwless_nonce'], $_POST['user_email'])) {
        return;
    }

    $nonce = sanitize_text_field(wp_unslash($_POST['pwless_nonce']));
    if (!wp_verify_nonce($nonce, 'pwless_login_action')) {
        pwless_redirect_login_form_with_feedback('<div class="error">Erro de validação. Por favor, tente novamente.</div>');
    }

    if (get_option('pwless_enable_altcha')) {
        $altcha_payload = isset($_POST['altcha']) ? sanitize_text_field(wp_unslash($_POST['altcha'])) : '';

        if (empty($altcha_payload) || !pwless_altcha_verify($altcha_payload)) {
            $email = isset($_POST['user_email']) ? sanitize_email(wp_unslash($_POST['user_email'])) : '';
            pwless_log_attempt($email, 'Falha - ALTCHA inválido');
            pwless_redirect_login_form_with_feedback('<div class="error">Verificação anti-spam falhou. Por favor, tente novamente.</div>', $email);
        }
    }

    $email = sanitize_email(wp_unslash($_POST['user_email']));
    if (!is_email($email)) {
        pwless_log_attempt($email, 'erro_email_invalido');
        pwless_redirect_login_form_with_feedback("<p class='error'>Email inválido.</p>", $email);
    }

    $user = get_user_by('email', $email);
    if (!$user) {
        pwless_log_attempt($email, 'usuario_nao_encontrado');
        pwless_redirect_login_form_with_feedback("<p class='error'>" . get_option('pwless_error_message') . "</p>", $email);
    }

    $token = wp_generate_password(20, false);
    $token_hash = wp_hash_password($token);
    $token_created = time();
    pwless_track_superseded_passwordless_token($user->ID);
    update_user_meta($user->ID, 'passwordless_login_token', $token_hash);
    update_user_meta($user->ID, 'passwordless_login_token_created', $token_created);

    $login_url = add_query_arg(array(
        'passwordless_login' => urlencode($token),
        'user' => $user->ID,
        'nonce' => wp_create_nonce('passwordless_login_' . $user->ID . '_' . $token_created)
    ), site_url());

    $expiry_seconds = get_option('pwless_link_expiry', 60) * 60; // Convertendo minutos para segundos
    $email_template = get_option('pwless_email_template');
    $email_content = str_replace(
        array('{login_url}', '{expiry_time}'),
        array($login_url, get_option('pwless_link_expiry', 60)), // Mostrando em minutos
        $email_template
    );

    $subject = get_option('pwless_email_subject', 'Seu link de login');

    if (pwless_send_html_mail($email, $subject, $email_content)) {
        pwless_log_attempt($email, 'email_enviado');
        pwless_redirect_login_form_with_feedback(
            "<p class='success'>" . str_replace('{expiry_time}', get_option('pwless_link_expiry', 60), get_option('pwless_success_message')) . "</p>"
        );
    }

    pwless_log_attempt($email, 'erro_envio_email');
    pwless_redirect_login_form_with_feedback("<p class='error'>Erro ao enviar email.</p>", $email);
}
add_action('template_redirect', 'pwless_handle_passwordless_login_form_submission');

// Função para exibir o formulário de login sem senha
function passwordless_login_form()
{
    if (is_user_logged_in()) {
        $redirect_url = get_option('pwless_redirect_url', home_url());
        ob_start();
        ?>
        <div class="already-logged-in">
            <p>Você já está logado!</p>
            <p>Você será redirecionado em <span id="countdown">5</span> segundos...</p>
            <a href="<?php echo esc_url($redirect_url); ?>" class="redirect-button">Ir para a página agora</a>
        </div>

        <style>
            .already-logged-in {
                text-align: center;
                padding: 20px;
                background: #f8f8f8;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin: 20px 0;
            }

            .redirect-button {
                display: inline-block;
                padding: 10px 20px;
                background-color: #2271b1;
                color: white;
                text-decoration: none;
                border-radius: 3px;
                margin-top: 10px;
            }

            .redirect-button:hover {
                background-color: #135e96;
                color: white;
            }
        </style>

        <script>
            document.addEventListener('DOMContentLoaded', function () {
                var count = 5;
                var countdown = document.getElementById('countdown');
                var timer = setInterval(function () {
                    count--;
                    countdown.textContent = count;
                    if (count <= 0) {
                        clearInterval(timer);
                        window.location.href = '<?php echo esc_js($redirect_url); ?>';
                    }
                }, 1000);
            });
        </script>
        <?php
        return ob_get_clean();
    }

    $feedback = pwless_get_login_form_feedback();
    $message = $feedback['message'];
    $email = $feedback['email'];

    return display_login_form($message, $email);
}

function display_login_form($message = '', $email = '')
{
    $form_email_label = get_option('pwless_form_email_label', 'Digite seu email:');
    $form_button_text = get_option('pwless_form_button_text', 'Enviar link');
    $enable_altcha = get_option('pwless_enable_altcha');

    ob_start();
    ?>
    <div class="pwless-login-form-wrapper">
        <?php if (!empty($message))
            echo $message; ?>

        <form method="post" action="<?php echo esc_url(pwless_get_login_form_redirect_url()); ?>" class="pwless-login-form">
            <?php wp_nonce_field('pwless_login_action', 'pwless_nonce'); ?>

            <div class="pwless-form-group">
                <label for="user_email"><?php echo esc_html($form_email_label); ?></label>
                <input type="email" name="user_email" id="user_email" value="<?php echo esc_attr($email); ?>" required>
            </div>

            <?php if ($enable_altcha): ?>
                <altcha-widget
                    challengeurl="<?php echo esc_url(admin_url('admin-ajax.php?action=pwless_altcha_challenge')); ?>"></altcha-widget>
                <script async defer src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js" type="module"></script>
            <?php endif; ?>

            <div class="pwless-form-group">
                <button type="submit"><?php echo esc_html($form_button_text); ?></button>
            </div>
        </form>
    </div>

    <style>
        .pwless-login-form-wrapper {
            max-width: 400px;
            margin: 20px auto;
            padding: 20px;
            background: #fff;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }

        .pwless-login-form .pwless-form-group {
            margin-bottom: 15px;
        }

        .pwless-login-form label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }

        .pwless-login-form input[type="email"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .pwless-login-form button {
            width: 100%;
            padding: 10px;
            background: #0073aa;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        .pwless-login-form button:hover {
            background: #005177;
        }

        .pwless-login-form .error {
            color: #dc3232;
            padding: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #dc3232;
            background: #fdf2f2;
        }

        .pwless-login-form .success {
            color: #46b450;
            padding: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #46b450;
            background: #ecf7ed;
        }

        altcha-widget {
            display: block;
            margin-bottom: 15px;
        }
    </style>
    <?php
    return ob_get_clean();
}
add_shortcode('passwordless_login', 'passwordless_login_form');

// Função para exibir o formulário de reset de senha
function pwless_reset_password_form()
{
    if (is_user_logged_in()) {
        $redirect_url = get_option('pwless_redirect_url', home_url());
        ob_start();
        ?>
        <div class="already-logged-in">
            <p>Você já está logado!</p>
            <p>Você será redirecionado em <span id="countdown">5</span> segundos...</p>
            <a href="<?php echo esc_url($redirect_url); ?>" class="redirect-button">Ir para a página agora</a>
        </div>

        <style>
            .already-logged-in {
                text-align: center;
                padding: 20px;
                background: #f8f8f8;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin: 20px 0;
            }

            .redirect-button {
                display: inline-block;
                padding: 10px 20px;
                background-color: #2271b1;
                color: white;
                text-decoration: none;
                border-radius: 3px;
                margin-top: 10px;
            }

            .redirect-button:hover {
                background-color: #135e96;
                color: white;
            }
        </style>

        <script>
            document.addEventListener('DOMContentLoaded', function () {
                var count = 5;
                var countdown = document.getElementById('countdown');
                var timer = setInterval(function () {
                    count--;
                    countdown.textContent = count;
                    if (count <= 0) {
                        clearInterval(timer);
                        window.location.href = '<?php echo esc_js($redirect_url); ?>';
                    }
                }, 1000);
            });
        </script>
        <?php
        return ob_get_clean();
    }

    $message = '';
    $email = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_email']) && check_admin_referer('pwless_reset_nonce', 'pwless_reset_nonce_field')) {
        $email = sanitize_email($_POST['user_email']);

        if (!is_email($email)) {
            $message = "<p class='error'>Por favor, insira um endereço de e-mail válido.</p>";
            pwless_log_attempt($email, 'reset_erro_email_invalido');
        } else {
            $user = get_user_by('email', $email);
            if (!$user) {
                $message = "<p class='error'>" . esc_html(get_option('pwless_reset_error_message')) . "</p>";
                pwless_log_attempt($email, 'reset_usuario_nao_encontrado');
            } else {
                $new_password = wp_generate_password(12, false);
                wp_set_password($new_password, $user->ID);

                $login_url = get_option('pwless_reset_login_url', home_url());
                $email_template = get_option('pwless_reset_email_template');
                $email_content = str_replace(
                    array('{new_password}', '{login_url}'),
                    array($new_password, $login_url),
                    $email_template
                );

                $subject = get_option('pwless_reset_email_subject');

                if (pwless_send_html_mail($email, $subject, $email_content)) {
                    $message = "<p class='success'>" . esc_html(get_option('pwless_reset_success_message')) . "</p>";
                    pwless_log_attempt($email, 'reset_senha_enviada');
                } else {
                    $message = "<p class='error'>Erro ao enviar email.</p>";
                    pwless_log_attempt($email, 'reset_erro_envio_email');
                }
            }
        }
    }

    ob_start();
    ?>
    <form method="post" class="reset-password-form" onsubmit="showLoader()">
        <?php wp_nonce_field('pwless_reset_nonce', 'pwless_reset_nonce_field'); ?>
        <h3><?php echo esc_html(get_option('pwless_reset_form_title')); ?></h3>
        <label for="user_email">Endereço de e-mail:</label>
        <input type="email" id="user_email" name="user_email" value="<?php echo esc_attr($email); ?>" required>
        <input type="submit" value="<?php echo esc_attr(get_option('pwless_reset_button_text')); ?>">
        <div><?php echo esc_html(get_option('pwless_reset_description')); ?></div>
        <div id="loader" style="display:none;">Enviando... <img
                src="<?php echo plugins_url('assets/loading.gif', __FILE__); ?>" alt="Carregando"></div>
        <?php echo wp_kses_post($message); ?>
    </form>

    <style>
        .reset-password-form {
            max-width: 400px;
            margin: auto;
            padding: 1em;
            border: 1px solid #ccc;
            border-radius: 1em;
        }

        .reset-password-form label {
            display: block;
            margin-bottom: 8px;
        }

        .reset-password-form input[type="email"],
        .reset-password-form input[type="submit"] {
            width: 100%;
            padding: 8px;
            margin-bottom: 12px;
        }

        .reset-password-form .error {
            color: red;
        }

        .reset-password-form .success {
            color: green;
        }

        #loader img {
            text-align: center;
            margin-top: 10px;
            height: 25px;
        }
    </style>

    <script>
        function showLoader() {
            document.getElementById('loader').style.display = 'block';
        }
    </script>
    <?php
    return ob_get_clean();
}
add_shortcode('passwordless_reset', 'pwless_reset_password_form');

function pwless_get_redirect_after_login()
{
    $redirect_url = get_option('pwless_redirect_url');
    if (empty($redirect_url)) {
        $redirect_url = home_url();
    }

    return $redirect_url;
}

function pwless_is_loggedin_plugin_active()
{
    return defined('LOGGEDIN_FILE')
        || class_exists('DuckDev\\Loggedin\\Core')
        || class_exists('Loggedin');
}

function pwless_loggedin_limit_error_message()
{
    $message = 'Você atingiu o limite máximo de logins simultâneos. Por favor, aguarde as sessões antigas expirarem ou faça logout em outro dispositivo.';

    if (!pwless_is_loggedin_plugin_active()) {
        return $message;
    }

    return apply_filters('loggedin_error_message', $message);
}

function pwless_loggedin_is_bypassed($user_id)
{
    if (!$user_id || !pwless_is_loggedin_plugin_active()) {
        return false;
    }

    return (bool) apply_filters('loggedin_bypass', false, $user_id);
}

function pwless_loggedin_get_active_sessions_count($user_id)
{
    if (!$user_id) {
        return 0;
    }

    if (!class_exists('WP_Session_Tokens')) {
        require_once ABSPATH . WPINC . '/class-wp-session-tokens.php';
    }

    $manager = WP_Session_Tokens::get_instance($user_id);
    return count($manager->get_all());
}

function pwless_loggedin_has_limit_reached($user_id)
{
    if (!$user_id || !pwless_is_loggedin_plugin_active()) {
        return false;
    }

    if (pwless_loggedin_is_bypassed($user_id)) {
        return false;
    }

    $maximum = intval(get_option('loggedin_maximum', 1));
    $count = pwless_loggedin_get_active_sessions_count($user_id);
    $reached = $count >= $maximum;

    return (bool) apply_filters('loggedin_reached_limit', $reached, $user_id, $count);
}

function pwless_loggedin_destroy_all_sessions($user_id)
{
    if (!$user_id) {
        return;
    }

    if (!class_exists('WP_Session_Tokens')) {
        require_once ABSPATH . WPINC . '/class-wp-session-tokens.php';
    }

    WP_Session_Tokens::get_instance($user_id)->destroy_all();
    do_action('loggedin_destroy_all_sessions', $user_id);
}

function pwless_loggedin_destroy_oldest_session($user_id)
{
    if (!$user_id) {
        return;
    }

    $sessions = get_user_meta($user_id, 'session_tokens', true);
    if (!is_array($sessions) || empty($sessions)) {
        return;
    }

    $oldest_token = '';
    $oldest_time = time();

    foreach ($sessions as $token => $session) {
        if (isset($session['login']) && intval($session['login']) < $oldest_time) {
            $oldest_time = intval($session['login']);
            $oldest_token = $token;
        }
    }

    if ($oldest_token === '') {
        return;
    }

    unset($sessions[$oldest_token]);
    update_user_meta($user_id, 'session_tokens', $sessions);

    do_action('loggedin_destroy_oldest_session', $user_id);
}

function pwless_apply_loggedin_session_limit($user_id)
{
    if (!$user_id || !pwless_is_loggedin_plugin_active()) {
        return array(
            'allowed' => true,
            'message' => '',
        );
    }

    $logic = get_option('loggedin_logic', 'allow');
    if (!in_array($logic, array('allow', 'logout_oldest', 'block'), true)) {
        $logic = 'allow';
    }

    if (!pwless_loggedin_has_limit_reached($user_id)) {
        return array(
            'allowed' => true,
            'message' => '',
        );
    }

    if ($logic === 'block') {
        do_action('loggedin_login_blocked', $user_id);

        return array(
            'allowed' => false,
            'message' => pwless_loggedin_limit_error_message(),
        );
    }

    if ($logic === 'logout_oldest') {
        pwless_loggedin_destroy_oldest_session($user_id);
    } else {
        pwless_loggedin_destroy_all_sessions($user_id);
    }

    return array(
        'allowed' => true,
        'message' => '',
    );
}

function pwless_user_can_login_with_loggedin_plugin($user_id)
{
    $result = pwless_apply_loggedin_session_limit($user_id);
    return !empty($result['allowed']);
}

function pwless_get_admin_generated_link_transient_key($admin_id, $user_id)
{
    return 'pwless_admin_link_' . intval($admin_id) . '_' . intval($user_id);
}

function pwless_get_admin_generated_link_data($user_id)
{
    $meta = get_user_meta($user_id, 'pwless_admin_generated_login_link', true);
    if (!is_array($meta)) {
        $meta = array();
    }

    return array(
        'token_hash' => isset($meta['token_hash']) ? $meta['token_hash'] : '',
        'token_value' => (isset($meta['token_value']) && is_string($meta['token_value'])) ? $meta['token_value'] : '',
        'created_at' => isset($meta['created_at']) ? intval($meta['created_at']) : 0,
        'expires_at' => isset($meta['expires_at']) ? intval($meta['expires_at']) : 0,
        'max_uses' => isset($meta['max_uses']) ? intval($meta['max_uses']) : 0,
        'uses' => isset($meta['uses']) ? intval($meta['uses']) : 0,
        'last_used_at' => isset($meta['last_used_at']) ? intval($meta['last_used_at']) : 0,
        'created_by' => isset($meta['created_by']) ? intval($meta['created_by']) : 0,
    );
}

function pwless_store_admin_generated_link_token($token)
{
    $token = is_string($token) ? $token : '';
    if ($token === '') {
        return '';
    }

    if (function_exists('openssl_encrypt')) {
        $key = hash('sha256', wp_salt('auth') . wp_salt('secure_auth'), true);
        $iv = substr(wp_generate_password(32, true, true), 0, 16);
        $encrypted = openssl_encrypt($token, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        if (is_string($encrypted)) {
            return 'enc:' . base64_encode($iv . $encrypted);
        }
    }

    return 'plain:' . base64_encode($token);
}

function pwless_restore_admin_generated_link_token($stored_value)
{
    if (!is_string($stored_value) || $stored_value === '') {
        return '';
    }

    if (strpos($stored_value, 'enc:') === 0 && function_exists('openssl_decrypt')) {
        $decoded = base64_decode(substr($stored_value, 4), true);
        if ($decoded !== false && strlen($decoded) > 16) {
            $iv = substr($decoded, 0, 16);
            $encrypted = substr($decoded, 16);
            $key = hash('sha256', wp_salt('auth') . wp_salt('secure_auth'), true);
            $token = openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

            if (is_string($token)) {
                return $token;
            }
        }
    }

    if (strpos($stored_value, 'plain:') === 0) {
        $decoded = base64_decode(substr($stored_value, 6), true);
        return is_string($decoded) ? $decoded : '';
    }

    return '';
}

function pwless_get_admin_generated_link_url($user_id, $admin_id = 0)
{
    $data = pwless_get_admin_generated_link_data($user_id);
    if (empty($data['token_hash'])) {
        return '';
    }

    $token = pwless_restore_admin_generated_link_token($data['token_value']);
    if ($token !== '') {
        return add_query_arg(
            array(
                'pwless_admin_login' => $token,
                'user' => $user_id,
            ),
            site_url('/')
        );
    }

    $admin_id = $admin_id ? intval($admin_id) : get_current_user_id();
    if ($admin_id > 0) {
        $transient_key = pwless_get_admin_generated_link_transient_key($admin_id, $user_id);
        $generated = get_transient($transient_key);
        if (is_array($generated) && !empty($generated['url'])) {
            return $generated['url'];
        }
    }

    return '';
}

function pwless_get_admin_generated_link_state($user_id, $admin_id = 0)
{
    $data = pwless_get_admin_generated_link_data($user_id);
    $has_active_link = !empty($data['token_hash']);
    $generated_url = $has_active_link ? pwless_get_admin_generated_link_url($user_id, $admin_id) : '';

    return array(
        'has_active_link' => $has_active_link,
        'generated_url' => $generated_url,
        'created_at' => ($has_active_link && $data['created_at']) ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $data['created_at']) : '-',
        'expires_at' => $has_active_link ? ($data['expires_at'] ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $data['expires_at']) : 'Nunca') : '-',
        'uses_info' => $has_active_link ? ($data['max_uses'] > 0 ? ($data['uses'] . ' / ' . $data['max_uses']) : ($data['uses'] . ' / Ilimitado')) : '-',
        'last_used' => ($has_active_link && $data['last_used_at']) ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $data['last_used_at']) : '-',
        'default_expiry' => $data['expires_at'] > $data['created_at'] ? intval(($data['expires_at'] - $data['created_at']) / MINUTE_IN_SECONDS) : 0,
        'default_max_uses' => $data['max_uses'] > 0 ? $data['max_uses'] : 0,
    );
}

function pwless_admin_generate_user_direct_link($user_id, $expiry_minutes, $max_uses, $admin_id = 0)
{
    $admin_id = $admin_id ? intval($admin_id) : get_current_user_id();
    $target_user = get_user_by('ID', $user_id);
    $created_at = current_time('timestamp');
    $expires_at = $expiry_minutes > 0 ? ($created_at + ($expiry_minutes * MINUTE_IN_SECONDS)) : 0;
    $token = wp_generate_password(48, false, false);

    update_user_meta($user_id, 'pwless_admin_generated_login_link', array(
        'token_hash' => wp_hash_password($token),
        'token_value' => pwless_store_admin_generated_link_token($token),
        'created_at' => $created_at,
        'expires_at' => $expires_at,
        'max_uses' => $max_uses,
        'uses' => 0,
        'last_used_at' => 0,
        'created_by' => $admin_id,
    ));

    $generated_url = add_query_arg(
        array(
            'pwless_admin_login' => $token,
            'user' => $user_id,
        ),
        site_url('/')
    );

    $transient_key = pwless_get_admin_generated_link_transient_key($admin_id, $user_id);
    set_transient($transient_key, array('url' => $generated_url), DAY_IN_SECONDS);

    if ($target_user) {
        pwless_log_attempt($target_user->user_email, 'admin_link_gerado');
    }

    return array(
        'message' => 'Link gerado com sucesso.',
        'generated_url' => $generated_url,
        'state' => pwless_get_admin_generated_link_state($user_id, $admin_id),
    );
}

function pwless_admin_revoke_user_direct_link($user_id, $admin_id = 0)
{
    $admin_id = $admin_id ? intval($admin_id) : get_current_user_id();
    $target_user = get_user_by('ID', $user_id);
    $transient_key = pwless_get_admin_generated_link_transient_key($admin_id, $user_id);

    delete_user_meta($user_id, 'pwless_admin_generated_login_link');
    delete_transient($transient_key);

    if ($target_user) {
        pwless_log_attempt($target_user->user_email, 'admin_link_revogado');
    }

    return array(
        'message' => 'Link revogado com sucesso.',
        'generated_url' => '',
        'state' => pwless_get_admin_generated_link_state($user_id, $admin_id),
    );
}

function pwless_render_admin_generated_link_assets()
{
    static $rendered = false;
    if ($rendered) {
        return;
    }

    $rendered = true;
    ?>
    <style>
        .pwless-admin-link-inline-fields {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 12px;
        }

        .pwless-admin-link-inline-fields label {
            display: flex;
            flex-direction: column;
            gap: 4px;
            font-weight: 600;
        }

        .pwless-admin-link-actions-group {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 12px;
        }

        .pwless-admin-link-notice {
            margin: 0 0 10px;
        }

        .pwless-admin-generated-link {
            width: 100%;
            max-width: 720px;
        }

        .pwless-generated-link-empty {
            margin: 4px 0 0;
            color: #646970;
            font-style: italic;
        }

        .pwless-login-links-table .column-user {
            min-width: 180px;
        }

        .pwless-login-links-table .column-email {
            min-width: 220px;
        }

        .pwless-login-links-table .column-link {
            min-width: 320px;
        }

        .pwless-login-links-table .column-actions {
            min-width: 270px;
        }

        .pwless-login-links-table .pwless-admin-generated-link {
            max-width: none;
        }

        .pwless-login-links-table .pwless-admin-link-inline-fields {
            margin-bottom: 10px;
        }

        .pwless-login-links-table .pwless-admin-link-inline-fields input {
            max-width: 90px;
        }

        .pwless-admin-link-user-name {
            font-weight: 600;
        }
    </style>
    <script>
        (function ($) {
            function getEmptyLinkMessage(hasActiveLink) {
                return hasActiveLink
                    ? 'Link indisponível para cópia nesta sessão. Gere novamente para obter o URL completo.'
                    : 'Nenhum link ativo para este usuário.';
            }

            function setLoading($manager, isLoading) {
                $manager.find('.pwless-admin-link-action').prop('disabled', isLoading);
            }

            function showNotice($manager, message, isError) {
                var $notice = $manager.find('.pwless-admin-link-notice');
                if (!$notice.length) {
                    return;
                }

                $notice.removeClass('notice-success notice-error').addClass(isError ? 'notice-error' : 'notice-success');
                $notice.find('p').text(message);
                $notice.show();
            }

            function updateState($manager, payload) {
                if (!payload || !payload.state) {
                    return;
                }

                var state = payload.state;
                var hasActiveLink = !!state.has_active_link;
                var generatedUrl = '';
                var hasGeneratedUrl = payload && Object.prototype.hasOwnProperty.call(payload, 'generated_url');

                if (hasGeneratedUrl) {
                    generatedUrl = payload.generated_url || '';
                } else if (state.generated_url) {
                    generatedUrl = state.generated_url;
                }

                $manager.find('.pwless-created-at').text(state.created_at || '-');
                $manager.find('.pwless-expires-at').text(state.expires_at || '-');
                $manager.find('.pwless-uses-info').text(state.uses_info || '-');
                $manager.find('.pwless-last-used').text(state.last_used || '-');
                $manager.find('.pwless-admin-link-expiry-minutes').val(state.default_expiry || 0);
                $manager.find('.pwless-admin-link-max-uses').val(state.default_max_uses || 0);

                if (hasActiveLink) {
                    $manager.find('.pwless-no-link-message').hide();
                    $manager.find('.pwless-revoke-link-btn').show();
                } else {
                    $manager.find('.pwless-no-link-message').show();
                    $manager.find('.pwless-revoke-link-btn').hide();
                }

                if (generatedUrl) {
                    $manager.find('.pwless-admin-generated-link').val(generatedUrl).show();
                    $manager.find('.pwless-generated-link-help').show();
                    $manager.find('.pwless-generated-link-empty').hide();
                    $manager.find('.pwless-copy-link-btn').show();
                } else {
                    $manager.find('.pwless-admin-generated-link').val('').hide();
                    $manager.find('.pwless-generated-link-help').hide();
                    $manager.find('.pwless-generated-link-empty').text(getEmptyLinkMessage(hasActiveLink)).show();
                    $manager.find('.pwless-copy-link-btn').hide();
                }
            }

            function runOperation($manager, operation) {
                setLoading($manager, true);
                $manager.find('.pwless-admin-link-notice').hide();

                $.post($manager.data('ajax-url'), {
                    action: 'pwless_manage_user_direct_link',
                    security: $manager.data('ajax-nonce'),
                    operation: operation,
                    user_id: $manager.data('user-id'),
                    expiry_minutes: $manager.find('.pwless-admin-link-expiry-minutes').val(),
                    max_uses: $manager.find('.pwless-admin-link-max-uses').val()
                }).done(function (response) {
                    if (!response || !response.success) {
                        showNotice($manager, response && response.data && response.data.message ? response.data.message : 'Erro ao processar a solicitação.', true);
                        return;
                    }

                    updateState($manager, response.data);
                    showNotice($manager, response.data && response.data.message ? response.data.message : 'Ação concluída.', false);
                }).fail(function () {
                    showNotice($manager, 'Erro de conexão ao processar a solicitação.', true);
                }).always(function () {
                    setLoading($manager, false);
                });
            }

            $(document).on('click', '.pwless-generate-link-btn', function (e) {
                e.preventDefault();
                runOperation($(this).closest('.pwless-admin-link-manager'), 'generate');
            });

            $(document).on('click', '.pwless-revoke-link-btn', function (e) {
                e.preventDefault();

                if (!window.confirm('Tem certeza que deseja revogar o link atual?')) {
                    return;
                }

                runOperation($(this).closest('.pwless-admin-link-manager'), 'revoke');
            });

            $(document).on('click', '.pwless-copy-link-btn', function (e) {
                e.preventDefault();

                var $manager = $(this).closest('.pwless-admin-link-manager');
                var $input = $manager.find('.pwless-admin-generated-link');
                var value = $input.val();

                if (!value) {
                    return;
                }

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(value).then(function () {
                        showNotice($manager, 'Link copiado para a área de transferência.', false);
                    }, function () {
                        showNotice($manager, 'Não foi possível copiar o link automaticamente.', true);
                    });
                    return;
                }

                $input.trigger('focus').trigger('select');

                try {
                    document.execCommand('copy');
                    showNotice($manager, 'Link copiado para a área de transferência.', false);
                } catch (err) {
                    showNotice($manager, 'Não foi possível copiar o link automaticamente.', true);
                }
            });
        })(jQuery);
    </script>
    <?php
}

function pwless_get_admin_generated_link_rows($admin_id = 0)
{
    $admin_id = $admin_id ? intval($admin_id) : get_current_user_id();
    $users = get_users(array(
        'meta_key' => 'pwless_admin_generated_login_link',
    ));

    if (empty($users)) {
        return array();
    }

    $rows = array();
    foreach ($users as $user) {
        $data = pwless_get_admin_generated_link_data($user->ID);
        $rows[] = array(
            'user' => $user,
            'data' => $data,
            'state' => pwless_get_admin_generated_link_state($user->ID, $admin_id),
        );
    }

    usort($rows, function ($left, $right) {
        if ($left['data']['created_at'] === $right['data']['created_at']) {
            return strcasecmp($left['user']->display_name, $right['user']->display_name);
        }

        return ($left['data']['created_at'] < $right['data']['created_at']) ? 1 : -1;
    });

    return $rows;
}

function pwless_render_admin_generated_link_row($user, $state)
{
    $ajax_nonce = wp_create_nonce('pwless_manage_user_direct_link_' . $user->ID);
    $ajax_url = admin_url('admin-ajax.php');
    ?>
    <tr class="pwless-admin-link-manager pwless-login-links-row" data-user-id="<?php echo intval($user->ID); ?>"
        data-ajax-url="<?php echo esc_url($ajax_url); ?>" data-ajax-nonce="<?php echo esc_attr($ajax_nonce); ?>">
        <td class="column-user">
            <a class="pwless-admin-link-user-name" href="<?php echo esc_url(get_edit_user_link($user->ID)); ?>">
                <?php echo esc_html($user->display_name); ?>
            </a>
        </td>
        <td class="column-email">
            <a href="mailto:<?php echo esc_attr($user->user_email); ?>">
                <?php echo esc_html($user->user_email); ?>
            </a>
        </td>
        <td class="column-link">
            <input type="text" class="regular-text code pwless-admin-generated-link" readonly
                value="<?php echo esc_attr($state['generated_url']); ?>"
                style="<?php echo !empty($state['generated_url']) ? '' : 'display:none;'; ?>">
            <p class="description pwless-generated-link-help"
                style="<?php echo !empty($state['generated_url']) ? '' : 'display:none;'; ?>">Copie este link e envie ao
                usuário.</p>
            <p class="description pwless-generated-link-empty"
                style="<?php echo empty($state['generated_url']) ? '' : 'display:none;'; ?>">
                <?php echo esc_html($state['has_active_link'] ? 'Link indisponível para cópia nesta sessão. Gere novamente para obter o URL completo.' : 'Nenhum link ativo para este usuário.'); ?>
            </p>
        </td>
        <td><span class="pwless-created-at"><?php echo esc_html($state['created_at']); ?></span></td>
        <td><span class="pwless-expires-at"><?php echo esc_html($state['expires_at']); ?></span></td>
        <td><span class="pwless-uses-info"><?php echo esc_html($state['uses_info']); ?></span></td>
        <td><span class="pwless-last-used"><?php echo esc_html($state['last_used']); ?></span></td>
        <td class="column-actions">
            <div class="pwless-admin-link-inline-fields">
                <label>
                    <span>Expiração (min)</span>
                    <input type="number" min="0" class="small-text pwless-admin-link-expiry-minutes"
                        value="<?php echo esc_attr($state['default_expiry']); ?>">
                </label>
                <label>
                    <span>Limite de usos</span>
                    <input type="number" min="0" class="small-text pwless-admin-link-max-uses"
                        value="<?php echo esc_attr($state['default_max_uses']); ?>">
                </label>
            </div>
            <div class="pwless-admin-link-actions-group">
                <button type="button" class="button button-primary pwless-admin-link-action pwless-generate-link-btn">Gerar
                    link</button>
                <button type="button" class="button button-secondary pwless-admin-link-action pwless-revoke-link-btn"
                    style="<?php echo $state['has_active_link'] ? '' : 'display:none;'; ?>">Revogar</button>
                <button type="button" class="button pwless-admin-link-action pwless-copy-link-btn"
                    style="<?php echo !empty($state['generated_url']) ? '' : 'display:none;'; ?>">Copiar</button>
            </div>
            <p class="pwless-no-link-message" style="<?php echo $state['has_active_link'] ? 'display:none;' : ''; ?>">
                <em>Nenhum link ativo para este usuário.</em>
            </p>
            <div class="pwless-admin-link-notice notice inline" style="display:none;">
                <p></p>
            </div>
        </td>
    </tr>
    <?php
}

function pwless_render_login_links_admin_tab()
{
    if (!current_user_can('manage_options')) {
        return;
    }

    pwless_render_admin_generated_link_assets();
    $rows = pwless_get_admin_generated_link_rows(get_current_user_id());
    ?>
    <div class="tab-content" id="login-links" style="display: none;">
        <h2>Links de login</h2>
        <p class="description">Aqui aparecem os links diretos gerados na edição de usuários. Se algum link antigo estiver
            sem URL para cópia, gere novamente para atualizar o registro.</p>
        <?php if (empty($rows)): ?>
            <p>Nenhum link direto foi gerado até o momento.</p>
        <?php else: ?>
            <table class="wp-list-table widefat striped pwless-login-links-table">
                <thead>
                    <tr>
                        <th class="column-user">Usuário</th>
                        <th class="column-email">Email</th>
                        <th class="column-link">Link</th>
                        <th>Criado em</th>
                        <th>Expira em</th>
                        <th>Usos</th>
                        <th>Último uso</th>
                        <th class="column-actions">Ações</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($rows as $row): ?>
                        <?php pwless_render_admin_generated_link_row($row['user'], $row['state']); ?>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
    <?php
}

function pwless_render_user_direct_login_card($user)
{
    if (!current_user_can('manage_options') || !current_user_can('edit_user', $user->ID)) {
        return;
    }

    $state = pwless_get_admin_generated_link_state($user->ID, get_current_user_id());
    $ajax_nonce = wp_create_nonce('pwless_manage_user_direct_link_' . $user->ID);
    $ajax_url = admin_url('admin-ajax.php');
    pwless_render_admin_generated_link_assets();
    ?>
    <h2>ZeroPass: Link direto de login</h2>
    <div class="pwless-admin-link-manager" data-user-id="<?php echo intval($user->ID); ?>"
        data-ajax-url="<?php echo esc_url($ajax_url); ?>" data-ajax-nonce="<?php echo esc_attr($ajax_nonce); ?>">
        <div class="pwless-admin-link-notice notice inline" style="display:none;">
            <p></p>
        </div>
        <table class="form-table" role="presentation">
            <tr>
                <th><label for="pwless_admin_link_expiry_minutes_<?php echo intval($user->ID); ?>">Expiração
                        (minutos)</label></th>
                <td>
                    <input type="number" id="pwless_admin_link_expiry_minutes_<?php echo intval($user->ID); ?>" min="0"
                        class="small-text pwless-admin-link-expiry-minutes"
                        value="<?php echo esc_attr($state['default_expiry']); ?>">
                    <p class="description">Use 0 para não expirar (padrão).</p>
                </td>
            </tr>
            <tr>
                <th><label for="pwless_admin_link_max_uses_<?php echo intval($user->ID); ?>">Limite de usos</label></th>
                <td>
                    <input type="number" id="pwless_admin_link_max_uses_<?php echo intval($user->ID); ?>" min="0"
                        class="small-text pwless-admin-link-max-uses"
                        value="<?php echo esc_attr($state['default_max_uses']); ?>">
                    <p class="description">Use 0 para usos ilimitados (padrão).</p>
                </td>
            </tr>
            <tr>
                <th>Ações</th>
                <td>
                    <button type="button"
                        class="button button-primary pwless-admin-link-action pwless-generate-link-btn">Gerar
                        link de login</button>
                    <button type="button" class="button button-secondary pwless-admin-link-action pwless-revoke-link-btn"
                        style="margin-left:8px;<?php echo $state['has_active_link'] ? '' : 'display:none;'; ?>">Revogar link
                        atual</button>
                    <button type="button" class="button pwless-admin-link-action pwless-copy-link-btn"
                        style="margin-left:8px;<?php echo !empty($state['generated_url']) ? '' : 'display:none;'; ?>">Copiar
                        link</button>
                    <p class="description">Tudo é processado em AJAX, sem refresh da página.</p>
                </td>
            </tr>
            <tr>
                <th><label for="pwless_admin_generated_link_<?php echo intval($user->ID); ?>">Link gerado</label></th>
                <td>
                    <input type="text" id="pwless_admin_generated_link_<?php echo intval($user->ID); ?>"
                        class="regular-text code pwless-admin-generated-link" readonly
                        value="<?php echo esc_attr($state['generated_url']); ?>"
                        style="<?php echo !empty($state['generated_url']) ? '' : 'display:none;'; ?>">
                    <p class="description pwless-generated-link-help"
                        style="<?php echo !empty($state['generated_url']) ? '' : 'display:none;'; ?>">Copie este link e
                        envie ao usuário.</p>
                    <p class="description pwless-generated-link-empty"
                        style="<?php echo empty($state['generated_url']) ? '' : 'display:none;'; ?>">
                        <?php echo esc_html($state['has_active_link'] ? 'Link indisponível para cópia nesta sessão. Gere novamente para obter o URL completo.' : 'Nenhum link ativo para este usuário.'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th>Status do link atual</th>
                <td>
                    <p class="pwless-no-link-message"
                        style="<?php echo $state['has_active_link'] ? 'display:none;' : ''; ?>">
                        <em>Nenhum link foi gerado para este usuário ainda.</em>
                    </p>
                    <p><strong>Criado em:</strong> <span
                            class="pwless-created-at"><?php echo esc_html($state['created_at']); ?></span>
                    </p>
                    <p><strong>Expira em:</strong> <span
                            class="pwless-expires-at"><?php echo esc_html($state['expires_at']); ?></span></p>
                    <p><strong>Usos:</strong> <span
                            class="pwless-uses-info"><?php echo esc_html($state['uses_info']); ?></span>
                    </p>
                    <p><strong>Último uso:</strong> <span
                            class="pwless-last-used"><?php echo esc_html($state['last_used']); ?></span>
                    </p>
                </td>
            </tr>
        </table>
    </div>
    <?php
}
add_action('show_user_profile', 'pwless_render_user_direct_login_card');
add_action('edit_user_profile', 'pwless_render_user_direct_login_card');

function pwless_ajax_manage_user_direct_link()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Acesso negado.'), 403);
    }

    $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
    if (!$user_id || !current_user_can('edit_user', $user_id)) {
        wp_send_json_error(array('message' => 'Usuário inválido ou sem permissão.'), 403);
    }

    $nonce = isset($_POST['security']) ? sanitize_text_field(wp_unslash($_POST['security'])) : '';
    if (!wp_verify_nonce($nonce, 'pwless_manage_user_direct_link_' . $user_id)) {
        wp_send_json_error(array('message' => 'Nonce inválido.'), 403);
    }

    $operation = isset($_POST['operation']) ? sanitize_key(wp_unslash($_POST['operation'])) : '';
    $admin_id = get_current_user_id();

    if ($operation === 'revoke') {
        wp_send_json_success(pwless_admin_revoke_user_direct_link($user_id, $admin_id));
    }

    if ($operation === 'generate') {
        $expiry_minutes = isset($_POST['expiry_minutes']) ? absint($_POST['expiry_minutes']) : 0;
        $max_uses = isset($_POST['max_uses']) ? absint($_POST['max_uses']) : 0;
        wp_send_json_success(pwless_admin_generate_user_direct_link($user_id, $expiry_minutes, $max_uses, $admin_id));
    }

    wp_send_json_error(array('message' => 'Operação inválida.'), 400);
}
add_action('wp_ajax_pwless_manage_user_direct_link', 'pwless_ajax_manage_user_direct_link');

function pwless_process_admin_generated_user_link()
{
    if (!isset($_GET['pwless_admin_login']) || !isset($_GET['user'])) {
        return;
    }

    $user_id = isset($_GET['user']) ? absint($_GET['user']) : 0;
    $token = isset($_GET['pwless_admin_login']) ? sanitize_text_field(wp_unslash($_GET['pwless_admin_login'])) : '';
    if (!$user_id || empty($token)) {
        return;
    }

    $user = get_user_by('ID', $user_id);
    $email = $user ? $user->user_email : 'unknown';
    $data = pwless_get_admin_generated_link_data($user_id);
    $now = current_time('timestamp');

    if (empty($data['token_hash']) || !wp_check_password($token, $data['token_hash'])) {
        pwless_log_attempt($email, 'admin_link_invalido');
        wp_die('Link inválido. Solicite um novo link ao administrador.', 'Link inválido', array('response' => 403));
    }

    if ($data['expires_at'] > 0 && $now > $data['expires_at']) {
        pwless_log_attempt($email, 'admin_link_expirado');
        wp_die('Este link expirou. Solicite um novo link ao administrador.', 'Link expirado', array('response' => 403));
    }

    if ($data['max_uses'] > 0 && $data['uses'] >= $data['max_uses']) {
        pwless_log_attempt($email, 'admin_link_limite');
        wp_die('Este link já atingiu o limite de usos.', 'Limite atingido', array('response' => 403));
    }

    $loggedin_check = pwless_apply_loggedin_session_limit($user_id);
    if (!$loggedin_check['allowed']) {
        pwless_log_attempt($email, 'admin_link_bloqueado');
        wp_die($loggedin_check['message'], 'Login bloqueado', array('response' => 403));
    }

    $data['uses'] = intval($data['uses']) + 1;
    $data['last_used_at'] = $now;
    update_user_meta($user_id, 'pwless_admin_generated_login_link', $data);

    wp_set_current_user($user_id);
    wp_set_auth_cookie($user_id);

    if ($user) {
        do_action('wp_login', $user->user_login, $user);
    }

    pwless_force_login_tracking($user_id);

    pwless_log_attempt($email, 'admin_link_usado');
    wp_safe_redirect(pwless_get_redirect_after_login());
    exit;
}
add_action('init', 'pwless_process_admin_generated_user_link', 1);

// Função auxiliar para forçar o registro de login compatível com outros plugins
function pwless_force_login_tracking($user_id)
{
    if (!$user_id)
        return;

    $login_data = array(
        'ip' => isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '',
        'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
        'time' => current_time('timestamp')
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

// Função para processar o login via link único
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

function pwless_get_passwordless_confirmation_page_defaults()
{
    return array(
        'title' => 'Confirmar login',
        'message' => 'Seu link foi validado. Para concluir o acesso, clique no botão abaixo. O login só será realizado após essa confirmação.',
        'button_label' => 'Entrar',
    );
}

function pwless_get_passwordless_confirmation_page_settings()
{
    $defaults = pwless_get_passwordless_confirmation_page_defaults();

    return array(
        'title' => get_option('pwless_confirmation_page_title', $defaults['title']),
        'message' => get_option('pwless_confirmation_page_message', $defaults['message']),
        'button_label' => get_option('pwless_confirmation_page_button_label', $defaults['button_label']),
    );
}

function pwless_get_request_method()
{
    if (!isset($_SERVER['REQUEST_METHOD'])) {
        return 'GET';
    }

    return strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])));
}

function pwless_render_passwordless_login_page($args = array())
{
    $confirmation_settings = pwless_get_passwordless_confirmation_page_settings();

    $args = wp_parse_args($args, array(
        'title' => $confirmation_settings['title'],
        'message' => $confirmation_settings['message'],
        'button_label' => $confirmation_settings['button_label'],
        'show_form' => false,
        'response_code' => 200,
        'user_id' => 0,
        'token' => '',
        'nonce' => '',
    ));

    status_header(max(100, intval($args['response_code'])));
    nocache_headers();

    $site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
    $home_link = home_url('/');
    $form_action = site_url('/');
    ?>
    <!DOCTYPE html>
    <html <?php language_attributes(); ?>>

    <head>
        <meta charset="<?php bloginfo('charset'); ?>">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="robots" content="noindex, nofollow">
        <title><?php echo esc_html($args['title']); ?> | <?php echo esc_html($site_name); ?></title>
        <style>
            body {
                margin: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 24px;
                background: #f4f7fb;
                color: #152033;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }

            .pwless-card {
                width: 100%;
                max-width: 480px;
                padding: 32px;
                background: #ffffff;
                border: 1px solid #d8e0ec;
                border-radius: 16px;
                box-shadow: 0 20px 50px rgba(21, 32, 51, 0.08);
                box-sizing: border-box;
            }

            .pwless-card h1 {
                margin: 0 0 16px;
                font-size: 28px;
                line-height: 1.2;
            }

            .pwless-card p {
                margin: 0 0 24px;
                font-size: 16px;
                line-height: 1.6;
            }

            .pwless-button,
            .pwless-link {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 100%;
                min-height: 48px;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
                text-decoration: none;
                box-sizing: border-box;
            }

            .pwless-button {
                border: 0;
                cursor: pointer;
                background: #152033;
                color: #ffffff;
            }

            .pwless-button:hover {
                background: #0f1726;
            }

            .pwless-link {
                border: 1px solid #d8e0ec;
                color: #152033;
                background: #ffffff;
            }
        </style>
    </head>

    <body>
        <main class="pwless-card">
            <h1><?php echo esc_html($args['title']); ?></h1>
            <p><?php echo nl2br(esc_html($args['message'])); ?></p>

            <?php if (!empty($args['show_form'])): ?>
                <form method="post" action="<?php echo esc_url($form_action); ?>">
                    <input type="hidden" name="pwless_action" value="confirm_passwordless_login">
                    <input type="hidden" name="user" value="<?php echo esc_attr(strval(absint($args['user_id']))); ?>">
                    <input type="hidden" name="passwordless_login" value="<?php echo esc_attr($args['token']); ?>">
                    <input type="hidden" name="nonce" value="<?php echo esc_attr($args['nonce']); ?>">
                    <button type="submit" class="pwless-button"><?php echo esc_html($args['button_label']); ?></button>
                </form>
            <?php else: ?>
                <a class="pwless-link" href="<?php echo esc_url($home_link); ?>">Voltar ao site</a>
            <?php endif; ?>
        </main>
    </body>

    </html>
    <?php
    exit;
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

            // Verifica se o nonce é válido e o token não expirou
            pwless_log_attempt($user ? $user->user_email : 'unknown', $validation['log_status']);
            echo '<p class="error">' . esc_html($validation['message']) . '</p>';
            return;
        }
        $user = $validation['user'];
        $loggedin_check = pwless_apply_loggedin_session_limit($user_id);
        if (!$loggedin_check['allowed']) {
            echo '<p class="error">' . esc_html($loggedin_check['message']) . '</p>';
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
function pwless_process_passwordless_login_confirmation_post()
{
    if (is_admin()) {
        return;
    }

    $request_method = pwless_get_request_method();

    if ($request_method !== 'POST') {
        return;
    }

    $action = isset($_POST['pwless_action']) ? sanitize_key(wp_unslash($_POST['pwless_action'])) : '';

    if ($action !== 'confirm_passwordless_login') {
        return;
    }

    $user_id = isset($_POST['user']) ? absint($_POST['user']) : 0;
    $token = isset($_POST['passwordless_login']) ? sanitize_text_field(wp_unslash($_POST['passwordless_login'])) : '';
    $nonce = isset($_POST['nonce']) ? sanitize_text_field(wp_unslash($_POST['nonce'])) : '';
    $validation = pwless_validate_passwordless_login($user_id, $token, $nonce);

    if (!$validation['valid']) {
        $user = $validation['user'];
        pwless_log_attempt($user ? $user->user_email : 'unknown', $validation['log_status']);
        pwless_render_passwordless_login_page(array(
            'title' => 'Link inválido',
            'message' => $validation['message'],
            'response_code' => 403,
        ));
    }

    $user = $validation['user'];

    $loggedin_check = pwless_apply_loggedin_session_limit($user_id);
    if (!$loggedin_check['allowed']) {
        pwless_render_passwordless_login_page(array(
            'title' => 'Login bloqueado',
            'message' => $loggedin_check['message'],
            'response_code' => 403,
        ));
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

function pwless_process_passwordless_login()
{
    if (is_admin()) {
        return;
    }

    $confirmation_settings = pwless_get_passwordless_confirmation_page_settings();
    $request_method = pwless_get_request_method();

    if ($request_method !== 'GET') {
        return;
    }

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
        pwless_render_passwordless_login_page(array(
            'title' => 'Link inválido',
            'message' => $validation['message'],
            'response_code' => 403,
        ));
    }

    pwless_render_passwordless_login_page(array(
        'title' => $confirmation_settings['title'],
        'message' => $confirmation_settings['message'],
        'button_label' => $confirmation_settings['button_label'],
        'show_form' => true,
        'user_id' => $user_id,
        'token' => $token,
        'nonce' => $nonce,
    ));
}
function process_passwordless_login()
{
    return pwless_process_passwordless_login();
}
add_action('init', 'pwless_process_passwordless_login_confirmation_post', 1);
add_action('template_redirect', 'pwless_process_passwordless_login', 1);

// Adiciona menu na área administrativa
function pwless_admin_menu()
{
    add_submenu_page(
        'tools.php',
        'Configurações de Login Sem Senha',
        'Login Sem Senha',
        'manage_options',
        'pwless-settings',
        'pwless_settings_page'
    );
}
add_action('admin_menu', 'pwless_admin_menu');

// Adiciona link de configurações na lista de plugins
function pwless_add_settings_link($links)
{
    $settings_link = '<a href="' . admin_url('tools.php?page=pwless-settings') . '">Configurações</a>';
    array_unshift($links, $settings_link);
    return $links;
}
$plugin = plugin_basename(__FILE__);
add_filter("plugin_action_links_$plugin", 'pwless_add_settings_link');

// Registra as configurações
function pwless_register_settings()
{
    register_setting('pwless_options', 'pwless_email_subject');
    register_setting('pwless_options', 'pwless_email_template');
    register_setting('pwless_options', 'pwless_link_expiry', 'intval');
    register_setting('pwless_options', 'pwless_form_email_label');
    register_setting('pwless_options', 'pwless_form_button_text');
    register_setting('pwless_options', 'pwless_success_message');
    register_setting('pwless_options', 'pwless_error_message');
    register_setting('pwless_options', 'pwless_enable_logging', 'boolval');
    register_setting('pwless_options', 'pwless_redirect_url', 'esc_url_raw');
    register_setting('pwless_options', 'pwless_confirmation_page_title');
    register_setting('pwless_options', 'pwless_confirmation_page_message');
    register_setting('pwless_options', 'pwless_confirmation_page_button_label');

    // Novas configurações para reset de senha
    register_setting('pwless_options', 'pwless_reset_email_subject');
    register_setting('pwless_options', 'pwless_reset_email_template');
    register_setting('pwless_options', 'pwless_reset_success_message');
    register_setting('pwless_options', 'pwless_reset_error_message');
    register_setting('pwless_options', 'pwless_reset_button_text');
    register_setting('pwless_options', 'pwless_reset_form_title');
    register_setting('pwless_options', 'pwless_reset_description');
    register_setting('pwless_options', 'pwless_reset_login_url', 'esc_url_raw');

    // Configurações do ALTCHA
    register_setting('pwless_options', 'pwless_altcha_hmac_key');
    register_setting('pwless_options', 'pwless_altcha_complexity', 'intval');
    register_setting('pwless_options', 'pwless_enable_altcha');
}
add_action('admin_init', 'pwless_register_settings');

// Configurações padrão para reset de senha
function pwless_set_default_reset_options()
{
    if (false === get_option('pwless_reset_email_subject')) {
        update_option('pwless_reset_email_subject', 'Sua nova senha');
        update_option('pwless_reset_email_template', 'Sua nova senha é: {new_password}<br><br>
            <a href="{login_url}" target="_blank">Clique aqui para fazer o login</a><br><br>
            Essa é uma senha temporária, após fazer o login por favor, altere sua senha assim que possível.');
        update_option('pwless_reset_success_message', 'Uma nova senha foi enviada para seu endereço de e-mail.');
        update_option('pwless_reset_error_message', 'Endereço de e-mail não encontrado.');
        update_option('pwless_reset_button_text', 'Enviar nova senha');
        update_option('pwless_reset_form_title', 'Resetar Senha');
        update_option('pwless_reset_description', 'Sua senha será alterada e enviada para seu email.');
    }
}
register_activation_hook(__FILE__, 'pwless_set_default_reset_options');

// Página de configurações
function pwless_settings_page()
{
    if (!current_user_can('manage_options')) {
        return;
    }

    $confirmation_defaults = pwless_get_passwordless_confirmation_page_defaults();

    // Salva as configurações padrão se não existirem
    if (false === get_option('pwless_email_subject')) {
        update_option('pwless_email_subject', 'Seu link de login');
        update_option('pwless_email_template', '<a href="{login_url}">Clique aqui para fazer login</a><br><br>O link tem validade de {expiry_time} minuto(s).');
        update_option('pwless_link_expiry', 60); // 60 minutos (1 hora) como padrão
        update_option('pwless_form_email_label', 'Digite seu email:');
        update_option('pwless_form_button_text', 'Enviar link');
        update_option('pwless_success_message', 'Link enviado para o email. O link tem validade de {expiry_time} minuto(s).');
        update_option('pwless_error_message', 'Usuário não encontrado.');
        update_option('pwless_enable_logging', true);
        update_option('pwless_redirect_url', home_url());
    }

    if (false === get_option('pwless_confirmation_page_title')) {
        update_option('pwless_confirmation_page_title', $confirmation_defaults['title']);
    }

    if (false === get_option('pwless_confirmation_page_message')) {
        update_option('pwless_confirmation_page_message', $confirmation_defaults['message']);
    }

    if (false === get_option('pwless_confirmation_page_button_label')) {
        update_option('pwless_confirmation_page_button_label', $confirmation_defaults['button_label']);
    }

    if (isset($_GET['settings-updated'])) {
        add_settings_error('pwless_messages', 'pwless_message', 'Configurações salvas', 'updated');
    }

    settings_errors('pwless_messages');
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <form action="options.php" method="post" novalidate>
            <?php
            settings_fields('pwless_options');
            ?>
            <div class="nav-tab-wrapper">
                <a href="#" class="nav-tab nav-tab-active" data-tab="email">Email</a>
                <a href="#" class="nav-tab" data-tab="form">Formulário</a>
                <a href="#" class="nav-tab" data-tab="confirmation">Confirmação</a>
                <a href="#" class="nav-tab" data-tab="security">Segurança</a>
                <a href="#" class="nav-tab" data-tab="login-links">Link de login</a>
                <a href="#" class="nav-tab" data-tab="reset">Reset de Senha</a>
                <a href="#" class="nav-tab" data-tab="shortcode">Shortcodes</a>
                <a href="#" class="nav-tab" data-tab="logs">Logs</a>
                <a href="#" class="nav-tab" data-tab="sobre">Sobre</a>
                <a href="#" class="nav-tab" data-tab="altcha">ALTCHA</a>
            </div>

            <div class="tab-content" id="email">
                <h2>Configurações de Email</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Assunto do Email</th>
                        <td>
                            <input type="text" name="pwless_email_subject"
                                value="<?php echo esc_attr(get_option('pwless_email_subject')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Modelo do Email</th>
                        <td>
                            <?php
                            wp_editor(
                                get_option('pwless_email_template'),
                                'pwless_email_template',
                                array(
                                    'textarea_name' => 'pwless_email_template',
                                    'textarea_rows' => 10,
                                    'media_buttons' => false
                                )
                            );
                            ?>
                            <p class="description">
                                Variáveis disponíveis: {login_url}, {expiry_time}
                            </p>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="tab-content" id="form" style="display: none;">
                <h2>Personalização do Formulário</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Label do Campo Email</th>
                        <td>
                            <input type="text" name="pwless_form_email_label"
                                value="<?php echo esc_attr(get_option('pwless_form_email_label')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Texto do Botão</th>
                        <td>
                            <input type="text" name="pwless_form_button_text"
                                value="<?php echo esc_attr(get_option('pwless_form_button_text')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem de Sucesso</th>
                        <td>
                            <input type="text" name="pwless_success_message"
                                value="<?php echo esc_attr(get_option('pwless_success_message')); ?>" class="regular-text">
                            <p class="description">Use {expiry_time} para mostrar o tempo de expiração</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem de Erro</th>
                        <td>
                            <input type="text" name="pwless_error_message"
                                value="<?php echo esc_attr(get_option('pwless_error_message')); ?>" class="regular-text">
                        </td>
                    </tr>
                </table>
            </div>

            <div class="tab-content" id="confirmation" style="display: none;">
                <h2>Página de Confirmação</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Título</th>
                        <td>
                            <input type="text" name="pwless_confirmation_page_title"
                                value="<?php echo esc_attr(get_option('pwless_confirmation_page_title', $confirmation_defaults['title'])); ?>"
                                class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem</th>
                        <td>
                            <textarea name="pwless_confirmation_page_message" rows="4"
                                class="large-text"><?php echo esc_textarea(get_option('pwless_confirmation_page_message', $confirmation_defaults['message'])); ?></textarea>
                            <p class="description">Texto exibido antes do clique final no botão de entrada.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Texto do Botão</th>
                        <td>
                            <input type="text" name="pwless_confirmation_page_button_label"
                                value="<?php echo esc_attr(get_option('pwless_confirmation_page_button_label', $confirmation_defaults['button_label'])); ?>"
                                class="regular-text">
                        </td>
                    </tr>
                </table>
            </div>

            <div class="tab-content" id="security" style="display: none;">
                <h2>Configurações de Segurança</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Tempo de Expiração do Link (minutos)</th>
                        <td>
                            <input type="number" name="pwless_link_expiry"
                                value="<?php echo esc_attr(get_option('pwless_link_expiry')); ?>" min="1" max="1440"
                                class="small-text">
                            <p class="description">Tempo de expiração do link de login em minutos. Padrão: 60 minutos (1
                                hora).</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">URL de Redirecionamento após Login</th>
                        <td>
                            <input type="url" name="pwless_redirect_url"
                                value="<?php echo esc_url(get_option('pwless_redirect_url', home_url())); ?>"
                                class="regular-text">
                            <p class="description">URL para onde o usuário será redirecionado após fazer login. Deixe em
                                branco para usar a página inicial.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Habilitar Logs</th>
                        <td>
                            <label>
                                <input type="checkbox" name="pwless_enable_logging" value="1" <?php checked(1, get_option('pwless_enable_logging'), true); ?>>
                                Registrar tentativas de login
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <?php pwless_render_login_links_admin_tab(); ?>

            <div class="tab-content" id="reset" style="display: none;">
                <h2>Configurações de Reset de Senha</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Assunto do Email de Reset</th>
                        <td>
                            <input type="text" name="pwless_reset_email_subject"
                                value="<?php echo esc_attr(get_option('pwless_reset_email_subject')); ?>"
                                class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Template do Email de Reset</th>
                        <td>
                            <?php
                            wp_editor(
                                get_option('pwless_reset_email_template'),
                                'pwless_reset_email_template',
                                array(
                                    'textarea_name' => 'pwless_reset_email_template',
                                    'textarea_rows' => 10,
                                    'media_buttons' => false
                                )
                            );
                            ?>
                            <p class="description">
                                Variáveis disponíveis: {new_password}, {login_url}
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Título do Formulário</th>
                        <td>
                            <input type="text" name="pwless_reset_form_title"
                                value="<?php echo esc_attr(get_option('pwless_reset_form_title')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Descrição do Formulário</th>
                        <td>
                            <input type="text" name="pwless_reset_description"
                                value="<?php echo esc_attr(get_option('pwless_reset_description')); ?>"
                                class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Texto do Botão</th>
                        <td>
                            <input type="text" name="pwless_reset_button_text"
                                value="<?php echo esc_attr(get_option('pwless_reset_button_text')); ?>"
                                class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem de Sucesso</th>
                        <td>
                            <input type="text" name="pwless_reset_success_message"
                                value="<?php echo esc_attr(get_option('pwless_reset_success_message')); ?>"
                                class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem de Erro</th>
                        <td>
                            <input type="text" name="pwless_reset_error_message"
                                value="<?php echo esc_attr(get_option('pwless_reset_error_message')); ?>"
                                class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">URL de Login no Reset</th>
                        <td>
                            <input type="url" name="pwless_reset_login_url"
                                value="<?php echo esc_url(get_option('pwless_reset_login_url', home_url())); ?>"
                                class="regular-text">
                            <p class="description">URL utilizada no placeholder {login_url} no email enviado (ex: página
                                contendo o formulário de login).</p>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="tab-content" id="shortcode" style="display: none;">
                <h2>Shortcodes Disponíveis</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Login Sem Senha</th>
                        <td>
                            <code>[passwordless_login]</code>
                            <p class="description">Use este shortcode para exibir o formulário de login sem senha.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Reset de Senha</th>
                        <td>
                            <code>[passwordless_reset]</code>
                            <p class="description">Use este shortcode para exibir o formulário de reset de senha.</p>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="tab-content" id="logs" style="display: none;">
                <div class="pwless-logs-toolbar">
                    <div>
                        <h2>Logs de Login</h2>
                        <p class="description">Navegue pelas páginas e atualize a lista sem recarregar a tela.</p>
                    </div>
                    <div class="pwless-logs-toolbar-actions">
                        <button type="button" class="button" id="pwless-refresh-logs">Atualizar</button>
                        <span class="spinner" id="pwless-logs-spinner"></span>
                    </div>
                </div>
                <div id="pwless-logs-feedback" class="notice inline" style="display:none;">
                    <p></p>
                </div>
                <div id="pwless-logs-container" data-ajax-url="<?php echo esc_url(admin_url('admin-ajax.php')); ?>"
                    data-security="<?php echo esc_attr(wp_create_nonce('pwless_fetch_logs')); ?>" data-current-page="1"
                    data-per-page="10">
                    <?php echo pwless_render_logs_table_markup(1, 10); ?>
                </div>
            </div>

            <div class="tab-content" id="sobre" style="display: none;">
                <h2>Sobre o Plugin</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Versão</th>
                        <td>
                            <?php
                            if (!function_exists('get_plugin_data')) {
                                require_once(ABSPATH . 'wp-admin/includes/plugin.php');
                            }
                            $plugin_data = get_plugin_data(__FILE__);
                            echo '<strong>' . esc_html($plugin_data['Version']) . '</strong>';
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Desenvolvido por</th>
                        <td>
                            <a href="https://projetoalfa.org" target="_blank">Giovani Tureck</a>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="tab-content" id="altcha" style="display: none;">
                <h2>Configurações do ALTCHA</h2>
                <p class="description">O <a href="https://altcha.org" target="_blank">ALTCHA</a> é uma alternativa ao
                    reCAPTCHA que respeita a privacidade dos usuários. Utiliza prova de trabalho (proof-of-work) sem
                    depender de serviços externos.</p>
                <table class="form-table">
                    <tr>
                        <th scope="row">Chave HMAC</th>
                        <td>
                            <input type="text" name="pwless_altcha_hmac_key"
                                value="<?php echo esc_attr(get_option('pwless_altcha_hmac_key')); ?>" class="regular-text">
                            <p class="description">Chave secreta usada para assinar os desafios. Use uma string aleatória
                                longa (mínimo 20 caracteres).</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Complexidade</th>
                        <td>
                            <input type="number" name="pwless_altcha_complexity"
                                value="<?php echo esc_attr(get_option('pwless_altcha_complexity', 50000)); ?>" min="1000"
                                max="1000000" class="small-text">
                            <p class="description">Número máximo para o desafio proof-of-work. Valores maiores = mais
                                seguro, porém mais lento para o navegador. Padrão: 50000.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Habilitar ALTCHA</th>
                        <td>
                            <label>
                                <input type="checkbox" name="pwless_enable_altcha" value="1" <?php checked(1, get_option('pwless_enable_altcha'), true); ?>>
                                Habilitar ALTCHA no formulário de login
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="submit-button-wrapper">
                <?php submit_button('Salvar Configurações'); ?>
            </div>
        </form>
    </div>

    <style>
        .tab-content {
            margin-top: 20px;
        }

        .nav-tab-wrapper {
            margin-bottom: 20px;
        }

        .pwless-logs-toolbar {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }

        .pwless-logs-toolbar h2 {
            margin-bottom: 4px;
        }

        .pwless-logs-toolbar-actions {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        #pwless-logs-container.is-loading {
            opacity: 0.6;
            pointer-events: none;
        }

        .pwless-logs-pagination {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-top: 12px;
            flex-wrap: wrap;
        }

        .pwless-logs-pagination-buttons {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }

        .pwless-logs-pagination-ellipsis {
            color: #646970;
            padding: 0 4px;
        }

        .pwless-logs-empty-state {
            margin: 0;
        }
    </style>

    <script>
        jQuery(document).ready(function ($) {
            var $settingsForm = $('form[action="options.php"]').first();
            var $logsContainer = $('#pwless-logs-container');
            var $logsFeedback = $('#pwless-logs-feedback');
            var $logsRefreshButton = $('#pwless-refresh-logs');
            var $logsSpinner = $('#pwless-logs-spinner');

            // Função para mostrar/esconder o botão de salvar
            function toggleSubmitButton(tab) {
                var $submitWrapper = $('.submit-button-wrapper');
                if (tab === 'login-links' || tab === 'shortcode' || tab === 'logs' || tab === 'sobre') {
                    $submitWrapper.hide();
                } else {
                    $submitWrapper.show();
                }
            }

            // Inicializa com a aba ativa
            toggleSubmitButton('email');

            $settingsForm.on('submit', function () {
                if (window.tinyMCE && typeof window.tinyMCE.triggerSave === 'function') {
                    window.tinyMCE.triggerSave();
                }
            });

            function showLogsFeedback(message, isError) {
                if (!$logsFeedback.length) {
                    return;
                }

                if (!message) {
                    $logsFeedback.hide().removeClass('notice-error notice-success').find('p').text('');
                    return;
                }

                $logsFeedback
                    .removeClass('notice-error notice-success')
                    .addClass(isError ? 'notice-error' : 'notice-success')
                    .show()
                    .find('p')
                    .text(message);
            }

            function setLogsLoading(isLoading) {
                if (!$logsContainer.length) {
                    return;
                }

                $logsContainer.toggleClass('is-loading', isLoading);
                $logsRefreshButton.prop('disabled', isLoading);

                if (isLoading) {
                    $logsSpinner.addClass('is-active');
                    return;
                }

                $logsSpinner.removeClass('is-active');
            }

            function loadLogsPage(page) {
                if (!$logsContainer.length) {
                    return;
                }

                var targetPage = parseInt(page, 10) || parseInt($logsContainer.attr('data-current-page'), 10) || 1;
                var perPage = parseInt($logsContainer.attr('data-per-page'), 10) || 10;

                showLogsFeedback('', false);
                setLogsLoading(true);

                $.ajax({
                    url: $logsContainer.data('ajax-url'),
                    type: 'POST',
                    dataType: 'json',
                    data: {
                        action: 'pwless_fetch_logs',
                        security: $logsContainer.data('security'),
                        page: targetPage,
                        per_page: perPage
                    }
                }).done(function (response) {
                    if (!response || !response.success || !response.data || typeof response.data.html === 'undefined') {
                        showLogsFeedback('Não foi possível carregar os logs.', true);
                        return;
                    }

                    $logsContainer.html(response.data.html);
                    $logsContainer.attr('data-current-page', response.data.current_page || 1);
                }).fail(function (xhr) {
                    var message = 'Não foi possível carregar os logs.';

                    if (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) {
                        message = xhr.responseJSON.data.message;
                    }

                    showLogsFeedback(message, true);
                }).always(function () {
                    setLogsLoading(false);
                });
            }

            $logsRefreshButton.on('click', function () {
                loadLogsPage();
            });

            $(document).on('click', '.pwless-logs-page-button', function () {
                if ($(this).prop('disabled')) {
                    return;
                }

                loadLogsPage($(this).data('page'));
            });

            $('.nav-tab').on('click', function (e) {
                e.preventDefault();
                var tab = $(this).data('tab');

                $('.nav-tab').removeClass('nav-tab-active');
                $(this).addClass('nav-tab-active');

                $('.tab-content').hide();
                $('#' + tab).show();

                // Mostra/esconde o botão de salvar
                toggleSubmitButton(tab);
            });
        });
    </script>
    <?php
}

// Criar tabela de logs na ativação do plugin
function pwless_create_log_table()
{
    global $wpdb;
    $table_name = $wpdb->prefix . 'pwless_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        email varchar(100) NOT NULL,
        status varchar(191) NOT NULL,
        ip_address varchar(45) NOT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}
register_activation_hook(__FILE__, 'pwless_create_log_table');

function pwless_maybe_upgrade_plugin()
{
    $installed_version = get_option('pwless_plugin_version', '0.0.0');

    if (version_compare($installed_version, PWLESS_PLUGIN_VERSION, '>=')) {
        return;
    }

    pwless_create_log_table();
    update_option('pwless_plugin_version', PWLESS_PLUGIN_VERSION);
}
add_action('plugins_loaded', 'pwless_maybe_upgrade_plugin');

function pwless_format_log_created_at($created_at)
{
    if (empty($created_at) || $created_at === '0000-00-00 00:00:00') {
        return '-';
    }

    try {
        $utc_datetime = new DateTimeImmutable($created_at, new DateTimeZone('UTC'));
        $brazil_datetime = $utc_datetime->setTimezone(new DateTimeZone('America/Sao_Paulo'));

        return $brazil_datetime->format('Y-m-d H:i:s');
    } catch (Exception $exception) {
        return $created_at;
    }
}

function pwless_get_logs_table_name()
{
    global $wpdb;

    return $wpdb->prefix . 'pwless_logs';
}

function pwless_logs_table_exists()
{
    global $wpdb;

    $table_name = pwless_get_logs_table_name();
    $existing_table_name = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table_name));

    return $existing_table_name === $table_name;
}

function pwless_get_logs_page_items($current_page, $total_pages)
{
    $items = array();
    $start = max(1, $current_page - 2);
    $end = min($total_pages, $current_page + 2);

    if ($start > 1) {
        $items[] = 1;

        if ($start > 2) {
            $items[] = 'ellipsis';
        }
    }

    for ($page = $start; $page <= $end; $page++) {
        $items[] = $page;
    }

    if ($end < $total_pages) {
        if ($end < ($total_pages - 1)) {
            $items[] = 'ellipsis';
        }

        $items[] = $total_pages;
    }

    return $items;
}

function pwless_get_logs_page_data($page = 1, $per_page = 10)
{
    global $wpdb;

    $per_page = max(1, min(50, absint($per_page) ?: 10));
    $requested_page = max(1, absint($page));
    $table_name = pwless_get_logs_table_name();

    if (!pwless_logs_table_exists()) {
        return array(
            'table_exists' => false,
            'logs' => array(),
            'current_page' => 1,
            'per_page' => $per_page,
            'total_items' => 0,
            'total_pages' => 1,
            'from_item' => 0,
            'to_item' => 0,
        );
    }

    $total_items = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");
    $total_pages = max(1, (int) ceil($total_items / $per_page));
    $current_page = min($requested_page, $total_pages);
    $offset = ($current_page - 1) * $per_page;
    $logs = array();

    if ($total_items > 0) {
        $query = $wpdb->prepare(
            "SELECT * FROM {$table_name} ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d",
            $per_page,
            $offset
        );
        $logs = $wpdb->get_results($query);
    }

    return array(
        'table_exists' => true,
        'logs' => $logs,
        'current_page' => $current_page,
        'per_page' => $per_page,
        'total_items' => $total_items,
        'total_pages' => $total_pages,
        'from_item' => $total_items > 0 ? ($offset + 1) : 0,
        'to_item' => $total_items > 0 ? min($offset + $per_page, $total_items) : 0,
    );
}

function pwless_render_logs_table_markup($page = 1, $per_page = 10)
{
    $logs_data = pwless_get_logs_page_data($page, $per_page);

    ob_start();

    if (!$logs_data['table_exists']) {
        echo '<p class="pwless-logs-empty-state">Tabela de logs não encontrada. Ative o logging nas configurações de segurança.</p>';

        return ob_get_clean();
    }

    if (empty($logs_data['logs'])) {
        echo '<p class="pwless-logs-empty-state">Nenhum log encontrado.</p>';

        return ob_get_clean();
    }
    ?>
    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>Data</th>
                <th>Email</th>
                <th>Status</th>
                <th>IP</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($logs_data['logs'] as $log): ?>
                <tr>
                    <td><?php echo esc_html(pwless_format_log_created_at($log->created_at)); ?></td>
                    <td><?php echo esc_html($log->email); ?></td>
                    <td><?php echo esc_html($log->status); ?></td>
                    <td><?php echo esc_html($log->ip_address); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <div class="pwless-logs-pagination">
        <span class="displaying-num">
            <?php
            echo esc_html(
                sprintf(
                    'Mostrando %1$s a %2$s de %3$s registros',
                    number_format_i18n($logs_data['from_item']),
                    number_format_i18n($logs_data['to_item']),
                    number_format_i18n($logs_data['total_items'])
                )
            );
            ?>
        </span>
        <?php if ($logs_data['total_pages'] > 1): ?>
            <div class="pwless-logs-pagination-buttons">
                <button type="button" class="button pwless-logs-page-button"
                    data-page="<?php echo esc_attr(max(1, $logs_data['current_page'] - 1)); ?>" <?php disabled($logs_data['current_page'] <= 1); ?>>
                    Anterior
                </button>
                <?php foreach (pwless_get_logs_page_items($logs_data['current_page'], $logs_data['total_pages']) as $page_item): ?>
                    <?php if ($page_item === 'ellipsis'): ?>
                        <span class="pwless-logs-pagination-ellipsis">&hellip;</span>
                    <?php else: ?>
                        <button type="button"
                            class="button pwless-logs-page-button <?php echo $page_item === $logs_data['current_page'] ? 'button-primary' : ''; ?>"
                            data-page="<?php echo esc_attr($page_item); ?>" <?php disabled($page_item === $logs_data['current_page']); ?>
                            <?php echo $page_item === $logs_data['current_page'] ? 'aria-current="page"' : ''; ?>>
                            <?php echo esc_html(number_format_i18n($page_item)); ?>
                        </button>
                    <?php endif; ?>
                <?php endforeach; ?>
                <button type="button" class="button pwless-logs-page-button"
                    data-page="<?php echo esc_attr(min($logs_data['total_pages'], $logs_data['current_page'] + 1)); ?>" <?php disabled($logs_data['current_page'] >= $logs_data['total_pages']); ?>>
                    Próxima
                </button>
            </div>
        <?php endif; ?>
    </div>
    <?php

    return ob_get_clean();
}

function pwless_ajax_fetch_logs()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Acesso negado.'), 403);
    }

    check_ajax_referer('pwless_fetch_logs', 'security');

    $page = isset($_POST['page']) ? absint(wp_unslash($_POST['page'])) : 1;
    $per_page = isset($_POST['per_page']) ? absint(wp_unslash($_POST['per_page'])) : 10;
    $logs_data = pwless_get_logs_page_data($page, $per_page);

    wp_send_json_success(array(
        'html' => pwless_render_logs_table_markup($page, $per_page),
        'current_page' => $logs_data['current_page'],
        'total_pages' => $logs_data['total_pages'],
    ));
}
add_action('wp_ajax_pwless_fetch_logs', 'pwless_ajax_fetch_logs');

// Função para registrar logs
function pwless_log_attempt($email, $status)
{
    if (!get_option('pwless_enable_logging')) {
        return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'pwless_logs';

    $wpdb->insert(
        $table_name,
        array(
            'email' => $email,
            'status' => sanitize_text_field($status),
            'ip_address' => isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '',
            'created_at' => current_time('mysql', true),
        ),
        array('%s', '%s', '%s', '%s')
    );
}

// Gera o desafio ALTCHA via AJAX
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

// Verifica o payload ALTCHA enviado pelo formulário
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





?>