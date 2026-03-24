<?php

$pwless_module_files = array(
    'forms.php',
    'direct-links.php',
    'auth.php',
    'admin.php',
    'logs.php',
    'altcha.php',
);

foreach ($pwless_module_files as $pwless_module_file) {
    require_once PWLESS_PLUGIN_DIR . 'includes/' . $pwless_module_file;
}

unset($pwless_module_file, $pwless_module_files);
