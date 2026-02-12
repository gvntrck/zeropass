<?php
/*
Plugin Name: ZeroPass Login
Plugin URI: https://github.com/gvntrck/zeropass
Description: Login sem complicações. Com o ZeroPass Login, seus usuários acessam sua plataforma com links seguros enviados por e-mail. Sem senhas, sem estresse – apenas segurança e simplicidade.
Version: 4.1.1
Author: Giovani Tureck - gvntrck
Author URI: https://projetoalfa.org
License: GPL v2 or later
Text Domain: zeropass-login
*/

// Função para exibir o formulário de login sem senha
function passwordless_login_form() {
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
            document.addEventListener('DOMContentLoaded', function() {
                var count = 5;
                var countdown = document.getElementById('countdown');
                var timer = setInterval(function() {
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

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_email'])) {
        if (!isset($_POST['pwless_nonce']) || !wp_verify_nonce($_POST['pwless_nonce'], 'pwless_login_action')) {
            $message = '<div class="error">Erro de validação. Por favor, tente novamente.</div>';
        } else {
            // Verifica o reCAPTCHA se estiver habilitado
            if (get_option('pwless_enable_recaptcha')) {
                $recaptcha_response = isset($_POST['g-recaptcha-response']) ? $_POST['g-recaptcha-response'] : '';
                $recaptcha_secret = get_option('pwless_recaptcha_secret_key');
                
                $verify_response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', array(
                    'body' => array(
                        'secret' => $recaptcha_secret,
                        'response' => $recaptcha_response
                    )
                ));

                if (is_wp_error($verify_response) || empty($recaptcha_response)) {
                    $message = '<div class="error">Por favor, complete o captcha.</div>';
                    pwless_log_attempt($_POST['user_email'], 'Falha - Captcha inválido');
                    return display_login_form($message, $email);
                }

                $response_body = json_decode(wp_remote_retrieve_body($verify_response));
                if (!$response_body->success) {
                    $message = '<div class="error">Verificação do captcha falhou. Por favor, tente novamente.</div>';
                    pwless_log_attempt($_POST['user_email'], 'Falha - Captcha falhou');
                    return display_login_form($message, $email);
                }
            }

            $email = sanitize_email($_POST['user_email']);
            if (!is_email($email)) {
                $message = "<p class='error'>Email inválido.</p>";
                pwless_log_attempt($email, 'erro_email_invalido');
            } else {
                $user = get_user_by('email', $email);
                if ($user) {
                    $token = wp_generate_password(20, false);
                    $token_hash = wp_hash_password($token);
                    $token_created = time();
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

                    $headers = array('Content-Type: text/html; charset=UTF-8');
                    $subject = get_option('pwless_email_subject', 'Seu link de login');
                    
                    if (wp_mail($email, $subject, $email_content, $headers)) {
                        $message = "<p class='success'>" . str_replace('{expiry_time}', get_option('pwless_link_expiry', 60), get_option('pwless_success_message')) . "</p>";
                        pwless_log_attempt($email, 'email_enviado');
                    } else {
                        $message = "<p class='error'>Erro ao enviar email.</p>";
                        pwless_log_attempt($email, 'erro_envio_email');
                    }
                } else {
                    $message = "<p class='error'>" . get_option('pwless_error_message') . "</p>";
                    pwless_log_attempt($email, 'usuario_nao_encontrado');
                }
            }
        }
    }

    return display_login_form($message, $email);
}

function display_login_form($message = '', $email = '') {
    $form_email_label = get_option('pwless_form_email_label', 'Digite seu email:');
    $form_button_text = get_option('pwless_form_button_text', 'Enviar link');
    $enable_recaptcha = get_option('pwless_enable_recaptcha');
    $recaptcha_site_key = get_option('pwless_recaptcha_site_key');

    ob_start();
    ?>
    <div class="pwless-login-form-wrapper">
        <?php if (!empty($message)) echo $message; ?>
        
        <form method="post" class="pwless-login-form">
            <?php wp_nonce_field('pwless_login_action', 'pwless_nonce'); ?>
            
            <div class="pwless-form-group">
                <label for="user_email"><?php echo esc_html($form_email_label); ?></label>
                <input type="email" name="user_email" id="user_email" value="<?php echo esc_attr($email); ?>" required>
            </div>

            <?php if ($enable_recaptcha && $recaptcha_site_key): ?>
                <div class="g-recaptcha" data-sitekey="<?php echo esc_attr($recaptcha_site_key); ?>"></div>
                <script src="https://www.google.com/recaptcha/api.js" async defer></script>
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
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
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
    .g-recaptcha {
        margin-bottom: 15px;
    }
    </style>
    <?php
    return ob_get_clean();
}
add_shortcode('passwordless_login', 'passwordless_login_form');

// Função para exibir o formulário de reset de senha
function pwless_reset_password_form() {
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
            document.addEventListener('DOMContentLoaded', function() {
                var count = 5;
                var countdown = document.getElementById('countdown');
                var timer = setInterval(function() {
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

                $login_url = home_url('/area-do-aluno/');
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
        <div id="loader" style="display:none;">Enviando... <img src="<?php echo plugins_url('assets/loading.gif', __FILE__); ?>" alt="Carregando"></div>
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
        .reset-password-form input[type="email"], .reset-password-form input[type="submit"] {
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

function pwless_get_redirect_after_login() {
    $redirect_url = get_option('pwless_redirect_url');
    if (empty($redirect_url)) {
        $redirect_url = home_url();
    }

    return $redirect_url;
}

function pwless_user_can_login_with_loggedin_plugin($user_id) {
    if (!class_exists('Loggedin')) {
        return true;
    }

    $loggedin = new Loggedin();
    $check = $loggedin->validate_block_logic(true, '', '', $user_id);

    return $check !== false;
}

function pwless_get_admin_generated_link_transient_key($admin_id, $user_id) {
    return 'pwless_admin_link_' . intval($admin_id) . '_' . intval($user_id);
}

function pwless_get_admin_generated_link_data($user_id) {
    $meta = get_user_meta($user_id, 'pwless_admin_generated_login_link', true);
    if (!is_array($meta)) {
        $meta = array();
    }

    return array(
        'token_hash'   => isset($meta['token_hash']) ? $meta['token_hash'] : '',
        'created_at'   => isset($meta['created_at']) ? intval($meta['created_at']) : 0,
        'expires_at'   => isset($meta['expires_at']) ? intval($meta['expires_at']) : 0,
        'max_uses'     => isset($meta['max_uses']) ? intval($meta['max_uses']) : 0,
        'uses'         => isset($meta['uses']) ? intval($meta['uses']) : 0,
        'last_used_at' => isset($meta['last_used_at']) ? intval($meta['last_used_at']) : 0,
        'created_by'   => isset($meta['created_by']) ? intval($meta['created_by']) : 0,
    );
}

function pwless_get_admin_generated_link_state($user_id) {
    $data = pwless_get_admin_generated_link_data($user_id);
    $has_active_link = !empty($data['token_hash']);

    return array(
        'has_active_link' => $has_active_link,
        'created_at'      => ($has_active_link && $data['created_at']) ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $data['created_at']) : '-',
        'expires_at'      => $has_active_link ? ($data['expires_at'] ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $data['expires_at']) : 'Nunca') : '-',
        'uses_info'       => $has_active_link ? ($data['max_uses'] > 0 ? ($data['uses'] . ' / ' . $data['max_uses']) : ($data['uses'] . ' / Ilimitado')) : '-',
        'last_used'       => ($has_active_link && $data['last_used_at']) ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $data['last_used_at']) : '-',
        'default_expiry'  => $data['expires_at'] > $data['created_at'] ? intval(($data['expires_at'] - $data['created_at']) / MINUTE_IN_SECONDS) : 0,
        'default_max_uses'=> $data['max_uses'] > 0 ? $data['max_uses'] : 0,
    );
}

function pwless_admin_generate_user_direct_link($user_id, $expiry_minutes, $max_uses, $admin_id = 0) {
    $admin_id = $admin_id ? intval($admin_id) : get_current_user_id();
    $target_user = get_user_by('ID', $user_id);
    $created_at = current_time('timestamp');
    $expires_at = $expiry_minutes > 0 ? ($created_at + ($expiry_minutes * MINUTE_IN_SECONDS)) : 0;
    $token = wp_generate_password(48, false, false);

    update_user_meta($user_id, 'pwless_admin_generated_login_link', array(
        'token_hash'   => wp_hash_password($token),
        'created_at'   => $created_at,
        'expires_at'   => $expires_at,
        'max_uses'     => $max_uses,
        'uses'         => 0,
        'last_used_at' => 0,
        'created_by'   => $admin_id,
    ));

    $generated_url = add_query_arg(
        array(
            'pwless_admin_login' => $token,
            'user'               => $user_id,
        ),
        site_url('/')
    );

    $transient_key = pwless_get_admin_generated_link_transient_key($admin_id, $user_id);
    set_transient($transient_key, array('url' => $generated_url), DAY_IN_SECONDS);

    if ($target_user) {
        pwless_log_attempt($target_user->user_email, 'admin_link_gerado');
    }

    return array(
        'message'       => 'Link gerado com sucesso.',
        'generated_url' => $generated_url,
        'state'         => pwless_get_admin_generated_link_state($user_id),
    );
}

function pwless_admin_revoke_user_direct_link($user_id, $admin_id = 0) {
    $admin_id = $admin_id ? intval($admin_id) : get_current_user_id();
    $target_user = get_user_by('ID', $user_id);
    $transient_key = pwless_get_admin_generated_link_transient_key($admin_id, $user_id);

    delete_user_meta($user_id, 'pwless_admin_generated_login_link');
    delete_transient($transient_key);

    if ($target_user) {
        pwless_log_attempt($target_user->user_email, 'admin_link_revogado');
    }

    return array(
        'message'       => 'Link revogado com sucesso.',
        'generated_url' => '',
        'state'         => pwless_get_admin_generated_link_state($user_id),
    );
}

function pwless_render_user_direct_login_card($user) {
    if (!current_user_can('manage_options') || !current_user_can('edit_user', $user->ID)) {
        return;
    }

    $state = pwless_get_admin_generated_link_state($user->ID);
    $transient_key = pwless_get_admin_generated_link_transient_key(get_current_user_id(), $user->ID);
    $generated = get_transient($transient_key);
    $generated_url = (is_array($generated) && !empty($generated['url'])) ? $generated['url'] : '';
    $ajax_nonce = wp_create_nonce('pwless_manage_user_direct_link_' . $user->ID);
    $ajax_url = admin_url('admin-ajax.php');
    ?>
    <h2>ZeroPass: Link direto de login</h2>
    <div id="pwless-admin-link-card">
        <div id="pwless-admin-link-notice" class="notice inline" style="display:none;"><p></p></div>
        <table class="form-table" role="presentation">
            <tr>
                <th><label for="pwless_admin_link_expiry_minutes">Expiração (minutos)</label></th>
                <td>
                    <input type="number" id="pwless_admin_link_expiry_minutes" min="0" class="small-text" value="<?php echo esc_attr($state['default_expiry']); ?>">
                    <p class="description">Use 0 para não expirar (padrão).</p>
                </td>
            </tr>
            <tr>
                <th><label for="pwless_admin_link_max_uses">Limite de usos</label></th>
                <td>
                    <input type="number" id="pwless_admin_link_max_uses" min="0" class="small-text" value="<?php echo esc_attr($state['default_max_uses']); ?>">
                    <p class="description">Use 0 para usos ilimitados (padrão).</p>
                </td>
            </tr>
            <tr>
                <th>Ações</th>
                <td>
                    <button type="button" id="pwless-generate-link-btn" class="button button-primary">Gerar link de login</button>
                    <button type="button" id="pwless-revoke-link-btn" class="button button-secondary" style="margin-left:8px;<?php echo $state['has_active_link'] ? '' : 'display:none;'; ?>">Revogar link atual</button>
                    <button type="button" id="pwless-copy-link-btn" class="button" style="margin-left:8px;<?php echo !empty($generated_url) ? '' : 'display:none;'; ?>">Copiar link</button>
                    <p class="description">Tudo é processado em AJAX, sem refresh da página.</p>
                </td>
            </tr>
            <tr id="pwless-generated-link-row" style="<?php echo !empty($generated_url) ? '' : 'display:none;'; ?>">
                <th><label for="pwless_admin_generated_link">Link gerado</label></th>
                <td>
                    <input type="text" id="pwless_admin_generated_link" class="regular-text code" readonly value="<?php echo esc_attr($generated_url); ?>" style="width:100%;max-width:720px;">
                    <p class="description">Copie este link e envie ao usuário.</p>
                </td>
            </tr>
            <tr>
                <th>Status do link atual</th>
                <td>
                    <p id="pwless-no-link-message" style="<?php echo $state['has_active_link'] ? 'display:none;' : ''; ?>"><em>Nenhum link foi gerado para este usuário ainda.</em></p>
                    <p><strong>Criado em:</strong> <span id="pwless-created-at"><?php echo esc_html($state['created_at']); ?></span></p>
                    <p><strong>Expira em:</strong> <span id="pwless-expires-at"><?php echo esc_html($state['expires_at']); ?></span></p>
                    <p><strong>Usos:</strong> <span id="pwless-uses-info"><?php echo esc_html($state['uses_info']); ?></span></p>
                    <p><strong>Último uso:</strong> <span id="pwless-last-used"><?php echo esc_html($state['last_used']); ?></span></p>
                </td>
            </tr>
        </table>
    </div>
    <script>
        (function($) {
            var ajaxUrl = <?php echo wp_json_encode($ajax_url); ?>;
            var ajaxNonce = <?php echo wp_json_encode($ajax_nonce); ?>;
            var userId = <?php echo intval($user->ID); ?>;

            var $notice = $('#pwless-admin-link-notice');
            var $generateBtn = $('#pwless-generate-link-btn');
            var $revokeBtn = $('#pwless-revoke-link-btn');
            var $copyBtn = $('#pwless-copy-link-btn');
            var $linkRow = $('#pwless-generated-link-row');
            var $linkInput = $('#pwless_admin_generated_link');
            var $noLinkMessage = $('#pwless-no-link-message');
            var $createdAt = $('#pwless-created-at');
            var $expiresAt = $('#pwless-expires-at');
            var $usesInfo = $('#pwless-uses-info');
            var $lastUsed = $('#pwless-last-used');

            function setLoading(isLoading) {
                $generateBtn.prop('disabled', isLoading);
                $revokeBtn.prop('disabled', isLoading);
                $copyBtn.prop('disabled', isLoading);
            }

            function showNotice(message, isError) {
                $notice.removeClass('notice-success notice-error').addClass(isError ? 'notice-error' : 'notice-success');
                $notice.find('p').text(message);
                $notice.show();
            }

            function updateState(payload) {
                if (!payload || !payload.state) {
                    return;
                }

                var state = payload.state;
                $createdAt.text(state.created_at || '-');
                $expiresAt.text(state.expires_at || '-');
                $usesInfo.text(state.uses_info || '-');
                $lastUsed.text(state.last_used || '-');

                if (state.has_active_link) {
                    $noLinkMessage.hide();
                    $revokeBtn.show();
                } else {
                    $noLinkMessage.show();
                    $revokeBtn.hide();
                }

                if (payload.generated_url) {
                    $linkInput.val(payload.generated_url);
                    $linkRow.show();
                    $copyBtn.show();
                } else {
                    $linkInput.val('');
                    $linkRow.hide();
                    $copyBtn.hide();
                }
            }

            function runOperation(operation) {
                setLoading(true);
                $notice.hide();

                $.post(ajaxUrl, {
                    action: 'pwless_manage_user_direct_link',
                    security: ajaxNonce,
                    operation: operation,
                    user_id: userId,
                    expiry_minutes: $('#pwless_admin_link_expiry_minutes').val(),
                    max_uses: $('#pwless_admin_link_max_uses').val()
                }).done(function(response) {
                    if (!response || !response.success) {
                        showNotice(response && response.data && response.data.message ? response.data.message : 'Erro ao processar a solicitação.', true);
                        return;
                    }

                    updateState(response.data);
                    showNotice(response.data && response.data.message ? response.data.message : 'Ação concluída.', false);
                }).fail(function() {
                    showNotice('Erro de conexão ao processar a solicitação.', true);
                }).always(function() {
                    setLoading(false);
                });
            }

            $generateBtn.on('click', function(e) {
                e.preventDefault();
                runOperation('generate');
            });

            $revokeBtn.on('click', function(e) {
                e.preventDefault();
                if (!window.confirm('Tem certeza que deseja revogar o link atual?')) {
                    return;
                }
                runOperation('revoke');
            });

            $copyBtn.on('click', function(e) {
                e.preventDefault();
                var value = $linkInput.val();
                if (!value) {
                    return;
                }

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(value).then(function() {
                        showNotice('Link copiado para a área de transferência.', false);
                    }, function() {
                        showNotice('Não foi possível copiar o link automaticamente.', true);
                    });
                    return;
                }

                $linkInput.trigger('focus').trigger('select');
                try {
                    document.execCommand('copy');
                    showNotice('Link copiado para a área de transferência.', false);
                } catch (err) {
                    showNotice('Não foi possível copiar o link automaticamente.', true);
                }
            });
        })(jQuery);
    </script>
    <?php
}
add_action('show_user_profile', 'pwless_render_user_direct_login_card');
add_action('edit_user_profile', 'pwless_render_user_direct_login_card');

function pwless_ajax_manage_user_direct_link() {
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

function pwless_process_admin_generated_user_link() {
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

    if (!pwless_user_can_login_with_loggedin_plugin($user_id)) {
        pwless_log_attempt($email, 'admin_link_bloqueado');
        wp_die('Você atingiu o limite máximo de logins simultâneos. Aguarde sessões antigas expirarem ou faça logout em outro dispositivo.', 'Login bloqueado', array('response' => 403));
    }

    $data['uses'] = intval($data['uses']) + 1;
    $data['last_used_at'] = $now;
    update_user_meta($user_id, 'pwless_admin_generated_login_link', $data);

    wp_set_current_user($user_id);
    wp_set_auth_cookie($user_id);

    if ($user) {
        do_action('wp_login', $user->user_login, $user);
    }

    pwless_log_attempt($email, 'admin_link_usado');
    wp_safe_redirect(pwless_get_redirect_after_login());
    exit;
}
add_action('init', 'pwless_process_admin_generated_user_link', 1);

// Função para processar o login via link único
function process_passwordless_login() {
    if (isset($_GET['passwordless_login']) && isset($_GET['user']) && isset($_GET['nonce'])) {
        $user_id = intval($_GET['user']);
        $token = sanitize_text_field(wp_unslash($_GET['passwordless_login']));
        $nonce = sanitize_text_field(wp_unslash($_GET['nonce']));
        $saved_token = get_user_meta($user_id, 'passwordless_login_token', true);
        $token_created = get_user_meta($user_id, 'passwordless_login_token_created', true);
        $expiry_seconds = get_option('pwless_link_expiry', 60) * 60; // Convertendo minutos para segundos

        // Verifica se o nonce é válido e o token não expirou
        $token_age = time() - intval($token_created);
        if (wp_verify_nonce($nonce, 'passwordless_login_' . $user_id . '_' . $token_created) && 
            $token && 
            wp_check_password($token, $saved_token) && 
            $token_age < $expiry_seconds) {
            
            if (!pwless_user_can_login_with_loggedin_plugin($user_id)) {
                echo '<p class="error">Você atingiu o limite máximo de logins simultâneos. Por favor, aguarde as sessões antigas expirarem ou faça logout em outro dispositivo.</p>';
                return;
            }
            
            wp_set_auth_cookie($user_id);
            delete_user_meta($user_id, 'passwordless_login_token');
            delete_user_meta($user_id, 'passwordless_login_token_created');
            
            $user = get_user_by('ID', $user_id);
            pwless_log_attempt($user ? $user->user_email : 'unknown', 'login_sucesso');
            
            wp_safe_redirect(pwless_get_redirect_after_login());
            exit;
        } else {
            $user = get_user_by('ID', $user_id);
            pwless_log_attempt($user ? $user->user_email : 'unknown', 'link_invalido_ou_expirado');
            echo '<p class="error">Link inválido ou expirado. Gere um novo link em <a href="https://cursosiname.com.br/login-sem-senha/">https://cursosiname.com.br/login-sem-senha/</a></p>';
        }
    }
}
add_action('init', 'process_passwordless_login');

// Adiciona menu na área administrativa
function pwless_admin_menu() {
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
function pwless_add_settings_link($links) {
    $settings_link = '<a href="' . admin_url('tools.php?page=pwless-settings') . '">Configurações</a>';
    array_unshift($links, $settings_link);
    return $links;
}
$plugin = plugin_basename(__FILE__);
add_filter("plugin_action_links_$plugin", 'pwless_add_settings_link');

// Registra as configurações
function pwless_register_settings() {
    register_setting('pwless_options', 'pwless_email_subject');
    register_setting('pwless_options', 'pwless_email_template');
    register_setting('pwless_options', 'pwless_link_expiry', 'intval');
    register_setting('pwless_options', 'pwless_form_email_label');
    register_setting('pwless_options', 'pwless_form_button_text');
    register_setting('pwless_options', 'pwless_success_message');
    register_setting('pwless_options', 'pwless_error_message');
    register_setting('pwless_options', 'pwless_enable_logging', 'boolval');
    register_setting('pwless_options', 'pwless_redirect_url');

    // Novas configurações para reset de senha
    register_setting('pwless_options', 'pwless_reset_email_subject');
    register_setting('pwless_options', 'pwless_reset_email_template');
    register_setting('pwless_options', 'pwless_reset_success_message');
    register_setting('pwless_options', 'pwless_reset_error_message');
    register_setting('pwless_options', 'pwless_reset_button_text');
    register_setting('pwless_options', 'pwless_reset_form_title');
    register_setting('pwless_options', 'pwless_reset_description');

    // Novas configurações para o reCAPTCHA
    register_setting('pwless_options', 'pwless_recaptcha_site_key');
    register_setting('pwless_options', 'pwless_recaptcha_secret_key');
    register_setting('pwless_options', 'pwless_enable_recaptcha');
}
add_action('admin_init', 'pwless_register_settings');

// Configurações padrão para reset de senha
function pwless_set_default_reset_options() {
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
function pwless_settings_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

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

    if (isset($_GET['settings-updated'])) {
        add_settings_error('pwless_messages', 'pwless_message', 'Configurações salvas', 'updated');
    }

    settings_errors('pwless_messages');
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <form action="options.php" method="post">
            <?php
            settings_fields('pwless_options');
            ?>
            <div class="nav-tab-wrapper">
                <a href="#" class="nav-tab nav-tab-active" data-tab="email">Email</a>
                <a href="#" class="nav-tab" data-tab="form">Formulário</a>
                <a href="#" class="nav-tab" data-tab="security">Segurança</a>
                <a href="#" class="nav-tab" data-tab="reset">Reset de Senha</a>
                <a href="#" class="nav-tab" data-tab="shortcode">Shortcodes</a>
                <a href="#" class="nav-tab" data-tab="logs">Logs</a>
                <a href="#" class="nav-tab" data-tab="sobre">Sobre</a>
                <a href="#" class="nav-tab" data-tab="recaptcha">reCAPTCHA</a>
            </div>

            <div class="tab-content" id="email">
                <h2>Configurações de Email</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Assunto do Email</th>
                        <td>
                            <input type="text" name="pwless_email_subject" value="<?php echo esc_attr(get_option('pwless_email_subject')); ?>" class="regular-text">
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
                            <input type="text" name="pwless_form_email_label" value="<?php echo esc_attr(get_option('pwless_form_email_label')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Texto do Botão</th>
                        <td>
                            <input type="text" name="pwless_form_button_text" value="<?php echo esc_attr(get_option('pwless_form_button_text')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem de Sucesso</th>
                        <td>
                            <input type="text" name="pwless_success_message" value="<?php echo esc_attr(get_option('pwless_success_message')); ?>" class="regular-text">
                            <p class="description">Use {expiry_time} para mostrar o tempo de expiração</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem de Erro</th>
                        <td>
                            <input type="text" name="pwless_error_message" value="<?php echo esc_attr(get_option('pwless_error_message')); ?>" class="regular-text">
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
                            <input type="number" name="pwless_link_expiry" value="<?php echo esc_attr(get_option('pwless_link_expiry')); ?>" min="1" max="1440" class="small-text">
                            <p class="description">Tempo de expiração do link de login em minutos. Padrão: 60 minutos (1 hora).</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">URL de Redirecionamento após Login</th>
                        <td>
                            <input type="url" name="pwless_redirect_url" value="<?php echo esc_url(get_option('pwless_redirect_url', home_url())); ?>" class="regular-text">
                            <p class="description">URL para onde o usuário será redirecionado após fazer login. Deixe em branco para usar a página inicial.</p>
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

            <div class="tab-content" id="reset" style="display: none;">
                <h2>Configurações de Reset de Senha</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Assunto do Email de Reset</th>
                        <td>
                            <input type="text" name="pwless_reset_email_subject" value="<?php echo esc_attr(get_option('pwless_reset_email_subject')); ?>" class="regular-text">
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
                            <input type="text" name="pwless_reset_form_title" value="<?php echo esc_attr(get_option('pwless_reset_form_title')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Descrição do Formulário</th>
                        <td>
                            <input type="text" name="pwless_reset_description" value="<?php echo esc_attr(get_option('pwless_reset_description')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Texto do Botão</th>
                        <td>
                            <input type="text" name="pwless_reset_button_text" value="<?php echo esc_attr(get_option('pwless_reset_button_text')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem de Sucesso</th>
                        <td>
                            <input type="text" name="pwless_reset_success_message" value="<?php echo esc_attr(get_option('pwless_reset_success_message')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mensagem de Erro</th>
                        <td>
                            <input type="text" name="pwless_reset_error_message" value="<?php echo esc_attr(get_option('pwless_reset_error_message')); ?>" class="regular-text">
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
                <h2>Logs de Login</h2>
                <?php
                global $wpdb;
                $table_name = $wpdb->prefix . 'pwless_logs';
                if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
                    $logs = $wpdb->get_results("SELECT * FROM $table_name ORDER BY created_at DESC LIMIT 10");
                    if ($logs) {
                        echo '<table class="wp-list-table widefat fixed striped">';
                        echo '<thead><tr><th>Data</th><th>Email</th><th>Status</th><th>IP</th></tr></thead>';
                        echo '<tbody>';
                        foreach ($logs as $log) {
                            echo '<tr>';
                            echo '<td>' . esc_html($log->created_at) . '</td>';
                            echo '<td>' . esc_html($log->email) . '</td>';
                            echo '<td>' . esc_html($log->status) . '</td>';
                            echo '<td>' . esc_html($log->ip_address) . '</td>';
                            echo '</tr>';
                        }
                        echo '</tbody></table>';
                    } else {
                        echo '<p>Nenhum log encontrado.</p>';
                    }
                } else {
                    echo '<p>Tabela de logs não encontrada. Ative o logging nas configurações de segurança.</p>';
                }
                ?>
            </div>

            <div class="tab-content" id="sobre" style="display: none;">
                <h2>Sobre o Plugin</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Versão</th>
                        <td>
                            <strong>4.0.0</strong>
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

            <div class="tab-content" id="recaptcha" style="display: none;">
                <h2>Configurações do reCAPTCHA</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Chave do Site do reCAPTCHA</th>
                        <td>
                            <input type="text" name="pwless_recaptcha_site_key" value="<?php echo esc_attr(get_option('pwless_recaptcha_site_key')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Chave Secreta do reCAPTCHA</th>
                        <td>
                            <input type="text" name="pwless_recaptcha_secret_key" value="<?php echo esc_attr(get_option('pwless_recaptcha_secret_key')); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Habilitar reCAPTCHA</th>
                        <td>
                            <label>
                                <input type="checkbox" name="pwless_enable_recaptcha" value="1" <?php checked(1, get_option('pwless_enable_recaptcha'), true); ?>>
                                Habilitar reCAPTCHA no formulário de login
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
    </style>

    <script>
        jQuery(document).ready(function($) {
            // Função para mostrar/esconder o botão de salvar
            function toggleSubmitButton(tab) {
                var $submitWrapper = $('.submit-button-wrapper');
                if (tab === 'shortcode' || tab === 'logs' || tab === 'sobre') {
                    $submitWrapper.hide();
                } else {
                    $submitWrapper.show();
                }
            }

            // Inicializa com a aba ativa
            toggleSubmitButton('email');

            $('.nav-tab').on('click', function(e) {
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
function pwless_create_log_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'pwless_logs';
    
    if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            email varchar(100) NOT NULL,
            status varchar(50) NOT NULL,
            ip_address varchar(45) NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
}
register_activation_hook(__FILE__, 'pwless_create_log_table');

// Função para registrar logs
function pwless_log_attempt($email, $status) {
    if (!get_option('pwless_enable_logging')) {
        return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'pwless_logs';
    
    $wpdb->insert(
        $table_name,
        array(
            'email' => $email,
            'status' => $status,
            'ip_address' => isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : ''
        ),
        array('%s', '%s', '%s')
    );
}

?>
