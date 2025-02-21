<?php
/**
 * Plugin Name: SafeGuardWP
 * Plugin URI: https://example.com/safeguardwp
 * Description: Advanced security plugin for WordPress
 * Version: 1.0.0
 * Author: Your Name
 * Author URI: https://example.com
 * Text Domain: safeguardwp
 */

defined('ABSPATH') or die('Access denied.');
/**
 * Plugin Name: SafeGuardWP
 * Plugin URI: https://example.com/safeguardwp
 * Description: Advanced security plugin for WordPress providing protection against common threats
 * Version: 1.0.0
 * Author: Your Name
 * Author URI: https://example.com
 * License: GPL v2 or later
 * Text Domain: safeguardwp
 * Domain Path: /languages
 * Requires at least: 5.0
 * Requires PHP: 7.2
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    error_log('SafeGuardWP: Attempted direct access blocked');
    die('Direct access not allowed');
}

// Define plugin constants
define('SAFEGUARD_VERSION', '1.0.0');
define('SAFEGUARD_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SAFEGUARD_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SAFEGUARD_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Activation Hook
function activate_safeguard() {
    error_log('SafeGuardWP: Starting plugin activation');

    try {
        if (!file_exists(SAFEGUARD_PLUGIN_DIR . 'includes/class-safeguard-activator.php')) {
            error_log('SafeGuardWP Error: Activator class file missing');
            throw new Exception('Required plugin file missing: class-safeguard-activator.php');
        }

        require_once SAFEGUARD_PLUGIN_DIR . 'includes/class-safeguard-activator.php';
        SafeGuard_Activator::activate();
        error_log('SafeGuardWP: Plugin activation completed successfully');
    } catch (Exception $e) {
        error_log('SafeGuardWP Activation Error: ' . $e->getMessage());
        error_log('Stack trace: ' . $e->getTraceAsString());
        wp_die(
            'Error activating SafeGuardWP plugin: ' . esc_html($e->getMessage()),
            'SafeGuardWP Activation Error',
            array('back_link' => true)
        );
    }
}
register_activation_hook(__FILE__, 'activate_safeguard');

// Deactivation Hook
function deactivate_safeguard() {
    error_log('SafeGuardWP: Starting plugin deactivation');

    $scheduled_tasks = array(
        'safeguard_scan_malware',
        'safeguard_check_files',
        'safeguard_check_permissions'
    );

    foreach ($scheduled_tasks as $task) {
        wp_clear_scheduled_hook($task);
    }

    error_log('SafeGuardWP: Plugin deactivated successfully');
}
register_deactivation_hook(__FILE__, 'deactivate_safeguard');

/**
 * Initialize plugin components
 */
function run_safeguard() {
    error_log('SafeGuardWP: Initializing plugin components');

    try {
        // Load plugin text domain
        load_plugin_textdomain('safeguardwp', false, dirname(SAFEGUARD_PLUGIN_BASENAME) . '/languages');
        error_log('SafeGuardWP: Text domain loaded');

        // Verify required files exist
        $required_files = array(
            'includes/class-safeguard-login.php',
            'includes/class-safeguard-firewall.php',
            'includes/class-safeguard-monitor.php',
            'includes/class-safeguard-malware.php',
            'includes/class-safeguard-2fa.php'
        );

        foreach ($required_files as $file) {
            $file_path = SAFEGUARD_PLUGIN_DIR . $file;
            if (!file_exists($file_path)) {
                error_log('SafeGuardWP Error: Required file missing - ' . $file);
                throw new Exception('Required plugin file missing: ' . $file);
            }
            require_once $file_path;
            error_log('SafeGuardWP: Loaded file - ' . $file);
        }

        // Include settings handler
        require_once SAFEGUARD_PLUGIN_DIR . 'includes/class-safeguard-settings.php';

        // Initialize components
        error_log('SafeGuardWP: Initializing core components');
        new SafeGuard_Login();
        new SafeGuard_Firewall();
        new SafeGuard_Monitor();
        new SafeGuard_Malware();
        new SafeGuard_2FA();
        new SafeGuard_Settings();
        error_log('SafeGuardWP: Core components initialized');

        // Initialize admin interface if in admin area
        if (is_admin()) {
            error_log('SafeGuardWP: Initializing admin interface');
            if (!file_exists(SAFEGUARD_PLUGIN_DIR . 'admin/class-safeguard-admin.php')) {
                error_log('SafeGuardWP Error: Admin class file missing');
                throw new Exception('Required plugin file missing: class-safeguard-admin.php');
            }
            require_once SAFEGUARD_PLUGIN_DIR . 'admin/class-safeguard-admin.php';
            $admin = new SafeGuard_Admin();
            $admin->init();
            error_log('SafeGuardWP: Admin interface initialized');
        }

        error_log('SafeGuardWP: Plugin initialization completed successfully');
    } catch (Exception $e) {
        error_log('SafeGuardWP Error: ' . $e->getMessage());
        error_log('Stack trace: ' . $e->getTraceAsString());
        add_action('admin_notices', function() use ($e) {
            printf(
                '<div class="error"><p>%s</p></div>',
                esc_html('SafeGuardWP Error: ' . $e->getMessage())
            );
        });
    }
}

// Initialize the plugin
add_action('plugins_loaded', 'run_safeguard');