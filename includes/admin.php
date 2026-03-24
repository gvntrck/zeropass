<?php

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

function pwless_add_settings_link($links)
{
    $settings_link = '<a href="' . admin_url('tools.php?page=pwless-settings') . '">Configurações</a>';
    array_unshift($links, $settings_link);
    return $links;
}
add_filter('plugin_action_links_' . PWLESS_PLUGIN_BASENAME, 'pwless_add_settings_link');

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
    register_setting('pwless_options', 'pwless_redirect_url');
    register_setting('pwless_options', 'pwless_reset_email_subject');
    register_setting('pwless_options', 'pwless_reset_email_template');
    register_setting('pwless_options', 'pwless_reset_success_message');
    register_setting('pwless_options', 'pwless_reset_error_message');
    register_setting('pwless_options', 'pwless_reset_button_text');
    register_setting('pwless_options', 'pwless_reset_form_title');
    register_setting('pwless_options', 'pwless_reset_description');
    register_setting('pwless_options', 'pwless_reset_login_url');
    register_setting('pwless_options', 'pwless_altcha_hmac_key');
    register_setting('pwless_options', 'pwless_altcha_complexity', 'intval');
    register_setting('pwless_options', 'pwless_enable_altcha');
}
add_action('admin_init', 'pwless_register_settings');

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
register_activation_hook(PWLESS_PLUGIN_FILE, 'pwless_set_default_reset_options');

function pwless_settings_page()
{
    if (!current_user_can('manage_options')) {
        return;
    }

    if (false === get_option('pwless_email_subject')) {
        update_option('pwless_email_subject', 'Seu link de login');
        update_option('pwless_email_template', '<a href="{login_url}">Clique aqui para fazer login</a><br><br>O link tem validade de {expiry_time} minuto(s).');
        update_option('pwless_link_expiry', 60);
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
            <?php settings_fields('pwless_options'); ?>
            <div class="nav-tab-wrapper">
                <a href="#" class="nav-tab nav-tab-active" data-tab="email">Email</a>
                <a href="#" class="nav-tab" data-tab="form">Formulário</a>
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
                                    'media_buttons' => false,
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
                                    'media_buttons' => false,
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
                <div id="pwless-logs-container"
                    data-ajax-url="<?php echo esc_url(admin_url('admin-ajax.php')); ?>"
                    data-security="<?php echo esc_attr(wp_create_nonce('pwless_fetch_logs')); ?>"
                    data-current-page="1"
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
                                require_once ABSPATH . 'wp-admin/includes/plugin.php';
                            }
                            $plugin_data = get_plugin_data(PWLESS_PLUGIN_FILE);
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
            var $logsContainer = $('#pwless-logs-container');
            var $logsFeedback = $('#pwless-logs-feedback');
            var $logsRefreshButton = $('#pwless-refresh-logs');
            var $logsSpinner = $('#pwless-logs-spinner');

            function toggleSubmitButton(tab) {
                var $submitWrapper = $('.submit-button-wrapper');
                if (tab === 'login-links' || tab === 'shortcode' || tab === 'logs' || tab === 'sobre') {
                    $submitWrapper.hide();
                } else {
                    $submitWrapper.show();
                }
            }

            toggleSubmitButton('email');

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

                toggleSubmitButton(tab);
            });
        });
    </script>
    <?php
}
