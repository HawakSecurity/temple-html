<?php
class SafeGuard_Monitor {
    private $core_files = array();
    private $recommended_permissions = array(
        'file' => 0644,
        'directory' => 0755
    );
    private $custom_paths = array();
    private $scan_frequency;
    private $last_scan;
    private $wpdb;

    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;

        // Initialize core files to monitor
        $this->core_files = json_decode(get_option('safeguard_critical_files', '[]'), true);
        if (empty($this->core_files)) {
            $this->core_files = array(
                ABSPATH . 'wp-config.php',
                ABSPATH . 'wp-login.php',
                ABSPATH . 'wp-admin/index.php',
                ABSPATH . 'wp-includes/version.php',
                ABSPATH . '.htaccess'
            );
        }

        // Get custom paths from settings
        $this->custom_paths = get_option('safeguard_monitored_paths', array());
        $this->scan_frequency = get_option('safeguard_scan_frequency', 'hourly');
        $this->last_scan = get_option('safeguard_last_scan', 0);

        // Register monitoring hooks if enabled
        if (get_option('safeguard_file_monitoring', 1)) {
            $this->setup_monitoring_hooks();
        }

        // Create necessary tables
        $this->maybe_create_tables();
    }

    private function maybe_create_tables() {
        $table_name = $this->wpdb->prefix . 'safeguard_file_changes';
        $charset_collate = $this->wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path varchar(255) NOT NULL,
            change_type varchar(50) NOT NULL,
            detected_at datetime NOT NULL,
            file_hash varchar(32),
            old_hash varchar(32),
            file_size bigint(20),
            file_permissions varchar(4),
            change_details text,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    private function setup_monitoring_hooks() {
        // Schedule file integrity checks
        if (!wp_next_scheduled('safeguard_check_files')) {
            wp_schedule_event(time(), $this->scan_frequency, 'safeguard_check_files');
        }

        // Schedule permission checks
        if (!wp_next_scheduled('safeguard_check_permissions')) {
            wp_schedule_event(time(), 'daily', 'safeguard_check_permissions');
        }

        // Add action hooks
        add_action('safeguard_check_files', array($this, 'check_file_integrity'));
        add_action('safeguard_check_permissions', array($this, 'check_directory_permissions'));
        add_action('updated_option', array($this, 'check_file_changes'), 10, 3);
        add_action('safeguard_check_files', array($this, 'scan_for_suspicious_files'));
    }

    public function check_file_integrity() {
        error_log('SafeGuardWP: Starting file integrity check');
        $files_to_check = array_merge($this->core_files, $this->get_custom_monitored_files());

        foreach ($files_to_check as $file) {
            if (file_exists($file)) {
                $current_hash = md5_file($file);
                $stored_hash = get_option('safeguard_file_hash_' . basename($file));
                $file_stat = stat($file);

                if (!$stored_hash) {
                    // New file being monitored
                    update_option('safeguard_file_hash_' . basename($file), $current_hash);
                    $this->log_file_change($file, 'added', array(
                        'hash' => $current_hash,
                        'size' => $file_stat['size'],
                        'permissions' => substr(sprintf('%o', fileperms($file)), -4)
                    ));
                } elseif ($stored_hash !== $current_hash) {
                    // File has been modified
                    $this->log_file_change($file, 'modified', array(
                        'old_hash' => $stored_hash,
                        'new_hash' => $current_hash,
                        'size' => $file_stat['size'],
                        'permissions' => substr(sprintf('%o', fileperms($file)), -4)
                    ));
                    update_option('safeguard_file_hash_' . basename($file), $current_hash);
                }
            } else {
                // File has been deleted
                $this->log_file_change($file, 'deleted', array());
                delete_option('safeguard_file_hash_' . basename($file));
            }
        }

        // Update last scan time
        update_option('safeguard_last_scan', time());
        error_log('SafeGuardWP: File integrity check completed');
    }

    private function get_custom_monitored_files() {
        $files = array();
        foreach ($this->custom_paths as $path) {
            if (is_dir($path)) {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
                );
                foreach ($iterator as $file) {
                    if ($file->isFile()) {
                        $files[] = $file->getPathname();
                    }
                }
            } elseif (is_file($path)) {
                $files[] = $path;
            }
        }
        return $files;
    }

    private function log_file_change($file_path, $change_type, $details = array()) {
        $table_name = $this->wpdb->prefix . 'safeguard_file_changes';

        // Ensure table exists
        $this->maybe_create_tables();

        $data = array(
            'file_path' => $file_path,
            'change_type' => $change_type,
            'detected_at' => current_time('mysql'),
            'file_hash' => isset($details['hash']) ? $details['hash'] : '',
            'old_hash' => isset($details['old_hash']) ? $details['old_hash'] : '',
            'file_size' => isset($details['size']) ? $details['size'] : 0,
            'file_permissions' => isset($details['permissions']) ? $details['permissions'] : '',
            'change_details' => json_encode($details)
        );

        $result = $this->wpdb->insert($table_name, $data);
        if ($result === false) {
            error_log('SafeGuardWP: Failed to log file change - ' . $this->wpdb->last_error);
        }

        // Send notification if enabled
        if (get_option('safeguard_notify_file_changes', 1)) {
            $this->notify_admin_file_change($file_path, $change_type, $details);
        }
    }

    private function notify_admin_file_change($file, $change_type, $details) {
        $admin_email = get_option('admin_email');
        $subject = sprintf('SafeGuardWP - File %s Detected', ucfirst($change_type));

        $message = sprintf(
            "A file change has been detected in your WordPress installation:\n\n" .
            "File: %s\n" .
            "Change Type: %s\n" .
            "Time: %s\n",
            $file,
            $change_type,
            current_time('mysql')
        );

        if (!empty($details)) {
            $message .= "\nChange Details:\n";
            foreach ($details as $key => $value) {
                $message .= sprintf("%s: %s\n", ucfirst($key), $value);
            }
        }

        $message .= "\nPlease investigate this change to ensure system security.";

        wp_mail($admin_email, $subject, $message);
    }

    public function check_directory_permissions() {
        error_log('SafeGuardWP: Starting directory permissions check');
        $directories_to_check = array(
            ABSPATH => $this->recommended_permissions['directory'],
            ABSPATH . 'wp-admin' => $this->recommended_permissions['directory'],
            ABSPATH . 'wp-includes' => $this->recommended_permissions['directory'],
            ABSPATH . 'wp-content' => $this->recommended_permissions['directory'],
            ABSPATH . 'wp-content/plugins' => $this->recommended_permissions['directory'],
            ABSPATH . 'wp-content/themes' => $this->recommended_permissions['directory'],
            ABSPATH . 'wp-content/uploads' => $this->recommended_permissions['directory']
        );

        $issues = array();
        foreach ($directories_to_check as $path => $recommended_perm) {
            if (!is_dir($path)) continue;

            $current_perm = substr(sprintf('%o', fileperms($path)), -4);
            if (intval($current_perm, 8) > $recommended_perm) {
                $issues[] = array(
                    'path' => $path,
                    'current' => $current_perm,
                    'recommended' => sprintf('%04o', $recommended_perm)
                );

                // Log permission issue
                $this->log_permission_issue($path, $current_perm, $recommended_perm);
            }
        }

        if (!empty($issues)) {
            $this->notify_admin_permissions($issues);
        }
        error_log('SafeGuardWP: Directory permissions check completed');
    }

    private function log_permission_issue($path, $current_perm, $recommended_perm) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'safeguard_logs';

        $wpdb->insert(
            $table_name,
            array(
                'event_type' => 'permission_issue',
                'event_description' => sprintf(
                    'Incorrect permissions detected on %s. Current: %s, Recommended: %s',
                    $path,
                    $current_perm,
                    sprintf('%04o', $recommended_perm)
                ),
                'severity_score' => 7,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%d', '%s')
        );
    }

    private function notify_admin_permissions($issues) {
        $admin_email = get_option('admin_email');
        $subject = 'SafeGuardWP - Security Permission Issues Detected';

        $message = "The following permission issues have been detected:\n\n";
        foreach ($issues as $issue) {
            $message .= sprintf(
                "Path: %s\n" .
                "Current Permission: %s\n" .
                "Recommended Permission: %s\n\n",
                $issue['path'],
                $issue['current'],
                $issue['recommended']
            );
        }

        $message .= "Please review and correct these permissions to maintain system security.";

        wp_mail($admin_email, $subject, $message);
    }

    private function scan_for_suspicious_files() {
        $this->scan_sensitive_directories();
    }

    private function scan_sensitive_directories() {
        $sensitive_dirs = array(
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes',
            ABSPATH . 'wp-content/uploads'
        );

        foreach ($sensitive_dirs as $dir) {
            if (!is_dir($dir)) continue;

            $dir_files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );

            foreach ($dir_files as $file) {
                $file_path = $file->getPathname();
                if ($this->is_suspicious_file($file_path)) {
                    $this->quarantine_file($file_path); // Quarantine suspicious files
                    $this->log_suspicious_file($file_path);
                }
            }
        }
    }


    private function is_suspicious_file($file) {
        $suspicious_extensions = array('php', 'phtml', 'php3', 'php4', 'php5', 'phps');
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));

        if (in_array($ext, $suspicious_extensions)) {
            // Check if file is in uploads directory
            if (strpos($file, 'wp-content/uploads') !== false) {
                return true;
            }

            // Check file content for suspicious patterns
            $content = file_get_contents($file);
            $suspicious_patterns = array(
                'eval(', 'base64_decode(', 'system(', 'exec(',
                'passthru(', 'shell_exec(', 'phpinfo()'
            );

            foreach ($suspicious_patterns as $pattern) {
                if (stripos($content, $pattern) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    private function log_suspicious_file($file_path) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'safeguard_logs';

        $wpdb->insert(
            $table_name,
            array(
                'event_type' => 'suspicious_file',
                'event_description' => sprintf(
                    'Suspicious file detected: %s',
                    $file_path
                ),
                'severity_score' => 8,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%d', '%s')
        );
    }

    private function quarantine_file($file_path) {
        // Implement file quarantine logic here.  This could involve moving the file
        // to a separate directory, renaming it, or deleting it depending on the
        // desired level of security.  For example:
        $quarantine_dir = ABSPATH . 'wp-content/quarantine';
        if (!is_dir($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
        }
        $new_file_path = $quarantine_dir . '/' . basename($file_path);
        rename($file_path, $new_file_path);

        //Log the quarantine event
        $this->log_quarantine_event($file_path, $new_file_path);
    }

    private function log_quarantine_event($original_path, $new_path){
        global $wpdb;
        $table_name = $wpdb->prefix . 'safeguard_logs';

        $wpdb->insert(
            $table_name,
            array(
                'event_type' => 'file_quarantined',
                'event_description' => sprintf(
                    'File quarantined: Original Path: %s, New Path: %s',
                    $original_path,
                    $new_path
                ),
                'severity_score' => 9,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%d', '%s')
        );
    }

    public function check_file_changes($option, $old_value, $value) {
        // Check if the updated option is related to monitored files or paths
        if ($option == 'safeguard_critical_files' || $option == 'safeguard_monitored_paths') {
            $this->check_file_integrity();
        }
    }
}