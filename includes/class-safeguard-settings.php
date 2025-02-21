<replit_final_file>
<?php
class SafeGuard_Settings {
    public function __construct() {
        add_action('wp_ajax_save_safeguard_settings', array($this, 'handle_settings_save'));
        add_action('admin_init', array($this, 'handle_direct_settings_save'));
    }

    public function handle_settings_save() {
        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
            return;
        }

        // Verify nonce for both AJAX and direct form submissions
        if (isset($_POST['safeguard_notification_nonce'])) {
            check_admin_referer('safeguard_notification_nonce', 'safeguard_notification_nonce');
        } elseif (isset($_POST['nonce'])) {
            check_ajax_referer('safeguard_nonce', 'nonce');
        }

        $form_id = isset($_POST['form_id']) ? sanitize_text_field($_POST['form_id']) : '';
        $form_data = array();

        if (isset($_POST['formData'])) {
            parse_str($_POST['formData'], $form_data);
        } else {
            // Fallback for direct form submission
            $form_data = $_POST;
        }

        $result = false;

        switch ($form_id) {
            case 'notification-settings-form':
                $result = $this->save_notification_settings($form_data);
                break;
            case 'firewall-settings-form':
                $result = $this->save_firewall_settings($form_data);
                break;
            case 'file-monitor-settings-form':
                $result = $this->save_file_monitor_settings($form_data);
                break;
            case 'safeguard-settings-form':
                $result = $this->save_general_settings($form_data);
                break;
        }

        if (defined('DOING_AJAX') && DOING_AJAX) {
            if ($result) {
                wp_send_json_success('Settings saved successfully');
            } else {
                wp_send_json_error('Failed to save settings');
            }
        } else {
            // Redirect back to the settings page for non-AJAX submissions
            wp_safe_redirect(admin_url('admin.php?page=safeguard-wp&tab=settings&updated=true'));
            exit;
        }
    }

    public function handle_direct_settings_save() {
        if (!isset($_POST['safeguard_settings_submit'])) {
            return;
        }

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        check_admin_referer('safeguard_settings_nonce');
        $this->handle_settings_save();
    }

    private function save_notification_settings($data) {
        try {
            $enable_attack = isset($data['enable_attack_notifications']);
            $enable_file = isset($data['enable_file_notifications']);
            $email = isset($data['notification_email']) ? sanitize_email($data['notification_email']) : '';

            update_option('safeguard_attack_notifications', $enable_attack);
            update_option('safeguard_file_notifications', $enable_file);

            if ($email && is_email($email)) {
                update_option('safeguard_notification_email', $email);
            }

            if (!defined('DOING_AJAX') || !DOING_AJAX) {
                wp_safe_redirect(admin_url('admin.php?page=safeguardwp&updated=true'));
                exit;
            }

            return true;
        } catch (Exception $e) {
            error_log('SafeGuardWP Error: Failed to save notification settings - ' . $e->getMessage());
            return false;
        }
    }

    private function save_firewall_settings($data) {
        try {
            if (isset($data['waf_mode'])) {
                update_option('safeguard_waf_mode', sanitize_text_field($data['waf_mode']));
            }
            if (isset($data['block_threshold'])) {
                update_option('safeguard_block_threshold', absint($data['block_threshold']));
            }
            return true;
        } catch (Exception $e) {
            error_log('SafeGuardWP Error: Failed to save firewall settings - ' . $e->getMessage());
            return false;
        }
    }

    private function save_file_monitor_settings($data) {
        try {
            update_option('safeguard_file_monitoring', isset($data['enable_file_monitoring']));
            if (isset($data['monitored_directories'])) {
                update_option('safeguard_monitored_directories', sanitize_textarea_field($data['monitored_directories']));
            }
            return true;
        } catch (Exception $e) {
            error_log('SafeGuardWP Error: Failed to save file monitor settings - ' . $e->getMessage());
            return false;
        }
    }

    private function save_general_settings($data) {
        try {
            update_option('safeguard_2fa_enabled', isset($data['enable_2fa']));
            if (isset($data['login_attempts'])) {
                update_option('safeguard_login_attempts', absint($data['login_attempts']));
            }
            if (isset($data['ban_duration'])) {
                update_option('safeguard_ban_duration', absint($data['ban_duration']));
            }
            update_option('safeguard_permanent_ban_attacks', isset($data['permanent_ban_attacks']));
            update_option('safeguard_country_blocking', isset($data['enable_country_blocking']));
            update_option('safeguard_malware_scanning', isset($data['enable_malware_scanning']));
            return true;
        } catch (Exception $e) {
            error_log('SafeGuardWP Error: Failed to save general settings - ' . $e->getMessage());
            return false;
        }
    }
}