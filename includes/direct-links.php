<?php

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
                    <button type="button" class="button button-primary pwless-admin-link-action pwless-generate-link-btn">Gerar
                        link de login</button>
                    <button type="button"
                        class="button button-secondary pwless-admin-link-action pwless-revoke-link-btn"
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
                    <p class="pwless-no-link-message" style="<?php echo $state['has_active_link'] ? 'display:none;' : ''; ?>">
                        <em>Nenhum link foi gerado para este usuário ainda.</em>
                    </p>
                    <p><strong>Criado em:</strong> <span class="pwless-created-at"><?php echo esc_html($state['created_at']); ?></span>
                    </p>
                    <p><strong>Expira em:</strong> <span
                            class="pwless-expires-at"><?php echo esc_html($state['expires_at']); ?></span></p>
                    <p><strong>Usos:</strong> <span class="pwless-uses-info"><?php echo esc_html($state['uses_info']); ?></span>
                    </p>
                    <p><strong>Último uso:</strong> <span class="pwless-last-used"><?php echo esc_html($state['last_used']); ?></span>
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

    pwless_force_login_tracking($user_id);

    pwless_log_attempt($email, 'admin_link_usado');
    wp_safe_redirect(pwless_get_redirect_after_login());
    exit;
}
add_action('init', 'pwless_process_admin_generated_user_link', 1);
