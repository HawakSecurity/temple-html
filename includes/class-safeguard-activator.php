<?php
class SafeGuard_Activator {
    public static function activate() {
        error_log('SafeGuardWP Activation: Starting activation process');

        try {
            // Verify WordPress environment
            if (!defined('ABSPATH')) {
                error_log('SafeGuardWP Activation Error: ABSPATH not defined');
                throw new Exception('WordPress core files not found. Please ensure WordPress is properly installed.');
            }

            // Verify required WordPress functions
            self::verify_wp_functions();

            error_log('SafeGuardWP Activation: WordPress environment verified');

            global $wpdb;
            if (!isset($wpdb)) {
                error_log('SafeGuardWP Activation Error: $wpdb not available');
                throw new Exception('WordPress database object not available.');
            }

            error_log('SafeGuardWP Activation: Creating database tables');

            // Create database tables with detailed error logging
            try {
                self::create_database_tables($wpdb);
                error_log('SafeGuardWP Activation: Database tables created successfully');
            } catch (Exception $e) {
                error_log('SafeGuardWP Activation Error: Database creation failed - ' . $e->getMessage());
                throw $e;
            }

            error_log('SafeGuardWP Activation: Initializing default settings');

            // Initialize default settings with logging
            try {
                self::initialize_default_settings();
                error_log('SafeGuardWP Activation: Default settings initialized successfully');
            } catch (Exception $e) {
                error_log('SafeGuardWP Activation Error: Settings initialization failed - ' . $e->getMessage());
                throw $e;
            }

            error_log('SafeGuardWP Activation: Plugin activated successfully');

        } catch (Exception $e) {
            $error_message = 'SafeGuardWP Activation Error: ' . $e->getMessage();
            error_log($error_message);
            error_log('Stack trace: ' . $e->getTraceAsString());
            throw new Exception($error_message);
        }
    }

    private static function verify_wp_functions() {
        $required_functions = array(
            'add_action',
            'add_filter',
            'wp_schedule_event',
            'wp_clear_scheduled_hook',
            'wp_next_scheduled',
            'get_option',
            'update_option',
            'delete_option',
            'wp_mail'
        );

        foreach ($required_functions as $function) {
            if (!function_exists($function)) {
                error_log("SafeGuardWP Activation Error: Required WordPress function '$function' not found");
                throw new Exception("Required WordPress function '$function' not found. Please check your WordPress installation.");
            }
        }

        // Verify dbDelta availability
        if (!function_exists('dbDelta')) {
            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            if (!function_exists('dbDelta')) {
                error_log('SafeGuardWP Activation Error: dbDelta function not available');
                throw new Exception('Could not load required WordPress database upgrade functions.');
            }
        }
    }

    private static function create_database_tables($wpdb) {
        $charset_collate = $wpdb->get_charset_collate();

        $tables = array(
            'logs' => "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}safeguard_logs (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                event_type varchar(50) NOT NULL,
                event_description text NOT NULL,
                ip_address varchar(45) DEFAULT NULL,
                user_agent text DEFAULT NULL,
                severity_score int(11) DEFAULT 0,
                request_uri text DEFAULT NULL,
                request_method varchar(10) DEFAULT NULL,
                additional_data longtext DEFAULT NULL,
                created_at datetime DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY event_type (event_type),
                KEY ip_address (ip_address),
                KEY severity_score (severity_score),
                KEY created_at (created_at)
            ) $charset_collate;",

            'blocked_ips' => "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}safeguard_blocked_ips (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                ip_address varchar(45) NOT NULL,
                reason text NOT NULL,
                blocked_until datetime NOT NULL,
                ban_count int(11) DEFAULT 1,
                first_ban_date datetime DEFAULT CURRENT_TIMESTAMP,
                last_ban_date datetime DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE KEY ip_address (ip_address),
                KEY blocked_until (blocked_until)
            ) $charset_collate;",

            'file_changes' => "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}safeguard_file_changes (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                file_path varchar(512) NOT NULL,
                file_hash varchar(64) DEFAULT NULL,
                change_type enum('modified','added','deleted') NOT NULL,
                old_hash varchar(64) DEFAULT NULL,
                file_size bigint(20) DEFAULT NULL,
                file_permissions varchar(4) DEFAULT NULL,
                detected_at datetime DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY file_path (file_path(191)),
                KEY detected_at (detected_at)
            ) $charset_collate;"
        );

        foreach ($tables as $table_name => $sql) {
            try {
                // Ensure the table is recreated with the new structure
                $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}safeguard_" . $table_name);
                $result = dbDelta($sql);
                error_log("SafeGuardWP Activation: Table creation result for $table_name - " . print_r($result, true));
            } catch (Exception $e) {
                error_log("SafeGuardWP Activation Error: Failed to create $table_name table - " . $e->getMessage());
                throw $e;
            }
        }
    }

    private static function initialize_default_settings() {
        error_log('SafeGuardWP Activation: Setting up default options');

        $default_settings = array(
            'safeguard_login_attempts' => 5,
            'safeguard_block_duration' => 60,
            'safeguard_file_monitoring' => 1,
            'safeguard_malware_scanning' => 1,
            'safeguard_notification_email' => get_option('admin_email'),
            'safeguard_min_password_length' => 12,
            'safeguard_enable_geo_blocking' => 1,
            'safeguard_enable_captcha' => 1,
            'safeguard_scan_frequency' => 'hourly',
            'safeguard_waf_mode' => 'moderate',
            'safeguard_log_retention_days' => 30,
            'safeguard_whitelisted_ips' => array('127.0.0.1', '::1'),
            'safeguard_critical_files' => json_encode(array(
                'wp-config.php',
                '.htaccess',
                'index.php',
                'wp-login.php',
                'wp-admin/index.php'
            ))
        );

        foreach ($default_settings as $option_name => $option_value) {
            error_log("SafeGuardWP Activation: Setting option - $option_name");
            try {
                if (get_option($option_name) === false) {
                    update_option($option_name, $option_value, 'yes');
                }
            } catch (Exception $e) {
                error_log("SafeGuardWP Activation Error: Failed to set option $option_name - " . $e->getMessage());
                throw new Exception("Failed to set option $option_name: " . $e->getMessage());
            }
        }
    }
    private static function setup_development_mode() {
        error_log('SafeGuardWP Activation: Configuring development mode settings');

        $dev_ips = array(
            '127.0.0.1',
            '::1',
            'localhost',
            '192.168.0.0/16',
            '172.16.0.0/12',
            '10.0.0.0/8'
        );

        try {
            update_option('safeguard_whitelisted_ips', $dev_ips);
            update_option('safeguard_waf_mode', 'learning');
            update_option('safeguard_block_duration', 5);
            update_option('safeguard_attack_threshold', 20);
            update_option('safeguard_login_attempts', 10);

            error_log('SafeGuardWP: Development mode enabled with relaxed security settings');
        } catch (Exception $e) {
            error_log('SafeGuardWP Activation Error: Failed to set development mode options - ' . $e->getMessage());
            throw new Exception('Failed to set development mode options: ' . $e->getMessage());
        }
    }
}