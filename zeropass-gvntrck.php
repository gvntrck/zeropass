<?php
/*
Plugin Name: ZeroPass Login
Plugin URI: https://github.com/gvntrck/zeropass
Description: Login sem complicações. Com o ZeroPass Login, seus usuários acessam sua plataforma com links seguros enviados por e-mail. Sem senhas, sem estresse – apenas segurança e simplicidade.
Version: 4.1.22
Author: Giovani Tureck - gvntrck
Author URI: https://projetoalfa.org
License: GPL v2 or later
Text Domain: zeropass-login
*/

if (!defined('PWLESS_PLUGIN_VERSION')) {
    define('PWLESS_PLUGIN_VERSION', '4.1.20');
}

if (!defined('PWLESS_PLUGIN_FILE')) {
    define('PWLESS_PLUGIN_FILE', __FILE__);
}

if (!defined('PWLESS_PLUGIN_DIR')) {
    define('PWLESS_PLUGIN_DIR', plugin_dir_path(__FILE__));
}

if (!defined('PWLESS_PLUGIN_BASENAME')) {
    define('PWLESS_PLUGIN_BASENAME', plugin_basename(__FILE__));
}

require_once PWLESS_PLUGIN_DIR . 'plugin-update-checker/plugin-update-checker.php';

$pwless_update_checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
    'https://github.com/gvntrck/zeropass/',
    __FILE__,
    'zeropass-gvntrck'
);

$pwless_update_checker->setBranch('beta');
$pwless_update_checker->setAuthentication('your-token-here');

require_once PWLESS_PLUGIN_DIR . 'includes/bootstrap.php';
