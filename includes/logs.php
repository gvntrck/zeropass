<?php

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

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
}
register_activation_hook(PWLESS_PLUGIN_FILE, 'pwless_create_log_table');

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
                    data-page="<?php echo esc_attr(max(1, $logs_data['current_page'] - 1)); ?>"
                    <?php disabled($logs_data['current_page'] <= 1); ?>>
                    Anterior
                </button>
                <?php foreach (pwless_get_logs_page_items($logs_data['current_page'], $logs_data['total_pages']) as $page_item): ?>
                    <?php if ($page_item === 'ellipsis'): ?>
                        <span class="pwless-logs-pagination-ellipsis">&hellip;</span>
                    <?php else: ?>
                        <button type="button"
                            class="button pwless-logs-page-button <?php echo $page_item === $logs_data['current_page'] ? 'button-primary' : ''; ?>"
                            data-page="<?php echo esc_attr($page_item); ?>"
                            <?php disabled($page_item === $logs_data['current_page']); ?>
                            <?php echo $page_item === $logs_data['current_page'] ? 'aria-current="page"' : ''; ?>>
                            <?php echo esc_html(number_format_i18n($page_item)); ?>
                        </button>
                    <?php endif; ?>
                <?php endforeach; ?>
                <button type="button" class="button pwless-logs-page-button"
                    data-page="<?php echo esc_attr(min($logs_data['total_pages'], $logs_data['current_page'] + 1)); ?>"
                    <?php disabled($logs_data['current_page'] >= $logs_data['total_pages']); ?>>
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

function pwless_log_attempt($email, $status)
{
    if (!get_option('pwless_enable_logging')) {
        return;
    }

    global $wpdb;
    $table_name = pwless_get_logs_table_name();

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
