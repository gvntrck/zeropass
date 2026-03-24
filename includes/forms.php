<?php

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

function pwless_get_logged_in_shortcode_redirect_url()
{
    return get_option('pwless_redirect_url', home_url());
}

function pwless_render_logged_in_notice($redirect_url)
{
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
        'nonce' => wp_create_nonce('passwordless_login_' . $user->ID . '_' . $token_created),
    ), site_url());

    $email_template = get_option('pwless_email_template');
    $email_content = str_replace(
        array('{login_url}', '{expiry_time}'),
        array($login_url, get_option('pwless_link_expiry', 60)),
        $email_template
    );

    $headers = array('Content-Type: text/html; charset=UTF-8');
    $subject = get_option('pwless_email_subject', 'Seu link de login');

    if (wp_mail($email, $subject, $email_content, $headers)) {
        pwless_log_attempt($email, 'email_enviado');
        pwless_redirect_login_form_with_feedback(
            "<p class='success'>" . str_replace('{expiry_time}', get_option('pwless_link_expiry', 60), get_option('pwless_success_message')) . "</p>"
        );
    }

    pwless_log_attempt($email, 'erro_envio_email');
    pwless_redirect_login_form_with_feedback("<p class='error'>Erro ao enviar email.</p>", $email);
}
add_action('template_redirect', 'pwless_handle_passwordless_login_form_submission');

function passwordless_login_form()
{
    if (is_user_logged_in()) {
        return pwless_render_logged_in_notice(pwless_get_logged_in_shortcode_redirect_url());
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
        <?php if (!empty($message)) {
            echo $message;
        } ?>

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

function pwless_reset_password_form()
{
    if (is_user_logged_in()) {
        return pwless_render_logged_in_notice(pwless_get_logged_in_shortcode_redirect_url());
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

                $headers = array('Content-Type: text/html; charset=UTF-8');
                $subject = get_option('pwless_reset_email_subject');

                if (wp_mail($email, $subject, $email_content, $headers)) {
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
                src="<?php echo plugins_url('assets/loading.gif', PWLESS_PLUGIN_FILE); ?>" alt="Carregando"></div>
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
