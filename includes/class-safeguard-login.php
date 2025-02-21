<?php
class SafeGuard_Login {
    private $wpdb;
    private $block_threshold;
    private $block_duration;
    private $enable_recaptcha;
    private $recaptcha_site_key;
    private $recaptcha_secret_key;

    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;

        // Initialize settings
        $this->block_threshold = get_option('safeguard_login_attempts', 5);
        $this->block_duration = get_option('safeguard_block_duration', 30);
        $this->enable_recaptcha = get_option('safeguard_enable_recaptcha', false);
        $this->recaptcha_site_key = get_option('safeguard_recaptcha_site_key', '');
        $this->recaptcha_secret_key = get_option('safeguard_recaptcha_secret_key', '');

        // Add hooks
        add_filter('authenticate', array($this, 'check_attempted_login'), 30, 3);
        add_action('wp_login_failed', array($this, 'log_failed_login'));
        add_action('wp_login', array($this, 'log_successful_login'), 10, 2);

        if ($this->enable_recaptcha) {
            add_action('login_form', array($this, 'add_recaptcha_to_login'));
        }
    }

    public function check_attempted_login($user, $username, $password) {
        if (empty($username)) {
            return $user;
        }

        $ip = $this->get_client_ip();

        // Check if IP is blocked
        if ($this->is_ip_blocked($ip)) {
            $this->log_security_event(
                'blocked_attempt',
                $ip,
                $username,
                'Blocked login attempt from banned IP'
            );
            return new WP_Error(
                'ip_blocked',
                'Access denied: Your IP has been temporarily blocked due to excessive failed login attempts.'
            );
        }

        // Verify reCAPTCHA if enabled
        if ($this->enable_recaptcha && !$this->verify_recaptcha()) {
            $this->log_security_event('recaptcha_failed', $ip, $username);
            return new WP_Error('recaptcha_failed', 'Please complete the reCAPTCHA verification.');
        }

        // Check for brute force attempts
        $attempts = $this->get_recent_failed_attempts($ip);
        if ($attempts >= $this->block_threshold) {
            $this->block_ip($ip, 'Too many failed login attempts');
            $this->notify_admin_blocked_ip($ip, $username, $attempts);
            return new WP_Error(
                'too_many_attempts',
                'Too many failed login attempts. Your IP has been temporarily blocked.'
            );
        }

        return $user;
    }

    private function is_ip_blocked($ip) {
        $table_name = $this->wpdb->prefix . 'safeguard_blocked_ips';
        $blocked = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT * FROM $table_name WHERE ip_address = %s AND blocked_until > NOW()",
            $ip
        ));
        return $blocked !== null;
    }

    private function get_recent_failed_attempts($ip) {
        $table_name = $this->wpdb->prefix . 'safeguard_logs';
        return $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(*) FROM $table_name 
            WHERE ip_address = %s 
            AND event_type = 'failed_login'
            AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)",
            $ip
        ));
    }

    public function log_failed_login($username) {
        $ip = $this->get_client_ip();
        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        $this->log_security_event(
            'failed_login',
            $ip,
            $username,
            'Failed login attempt',
            array(
                'user_agent' => $user_agent,
                'request_uri' => $_SERVER['REQUEST_URI']
            )
        );

        // Check for distributed attacks
        $this->check_distributed_attack($ip, $username);
    }

    public function log_successful_login($username, $user) {
        $ip = $this->get_client_ip();
        $this->log_security_event(
            'successful_login',
            $ip,
            $username,
            'Successful login',
            array('user_id' => $user->ID)
        );
    }

    private function log_security_event($event_type, $ip, $username, $description = '', $additional_data = array()) {
        $table_name = $this->wpdb->prefix . 'safeguard_logs';

        $data = array(
            'event_type' => $event_type,
            'event_description' => $description ?: $event_type,
            'ip_address' => $ip,
            'username' => $username,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'additional_data' => json_encode($additional_data),
            'created_at' => current_time('mysql')
        );

        $this->wpdb->insert($table_name, $data, array('%s', '%s', '%s', '%s', '%s', '%s', '%s'));
    }

    private function block_ip($ip, $reason) {
        $table_name = $this->wpdb->prefix . 'safeguard_blocked_ips';

        // Get current ban count
        $existing_ban = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT ban_count FROM $table_name WHERE ip_address = %s",
            $ip
        ));

        $ban_count = $existing_ban ? $existing_ban->ban_count + 1 : 1;

        // Exponential backoff for repeat offenders (30min, 1h, 2h, 4h, etc.)
        $block_minutes = $this->block_duration * pow(2, $ban_count - 1);
        $blocked_until = date('Y-m-d H:i:s', strtotime("+{$block_minutes} minutes"));

        $this->wpdb->replace(
            $table_name,
            array(
                'ip_address' => $ip,
                'reason' => $reason,
                'blocked_until' => $blocked_until,
                'ban_count' => $ban_count,
                'last_ban_date' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%d', '%s')
        );
    }

    private function check_distributed_attack($ip, $username) {
        $table_name = $this->wpdb->prefix . 'safeguard_logs';

        // Check for same username from multiple IPs
        $ip_count = $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(DISTINCT ip_address) FROM $table_name 
            WHERE username = %s 
            AND event_type = 'failed_login'
            AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
            $username
        ));

        if ($ip_count > 10) {
            $this->notify_admin_distributed_attack($username, $ip_count);
        }

        // Check for same IP targeting multiple usernames
        $username_count = $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(DISTINCT username) FROM $table_name 
            WHERE ip_address = %s 
            AND event_type = 'failed_login'
            AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
            $ip
        ));

        if ($username_count > 5) {
            $this->block_ip($ip, 'Multiple username attack detected');
        }
    }

    private function verify_recaptcha() {
        if (!isset($_POST['g-recaptcha-response'])) {
            return false;
        }

        $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', array(
            'body' => array(
                'secret' => $this->recaptcha_secret_key,
                'response' => $_POST['g-recaptcha-response'],
                'remoteip' => $this->get_client_ip()
            )
        ));

        if (is_wp_error($response)) {
            return false;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        return isset($body['success']) && $body['success'];
    }

    public function add_recaptcha_to_login() {
        if (!empty($this->recaptcha_site_key)) {
            echo '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';
            echo '<div class="g-recaptcha" data-sitekey="' . esc_attr($this->recaptcha_site_key) . '"></div>';
        }
    }

    private function notify_admin_blocked_ip($ip, $username, $attempts) {
        $admin_email = get_option('admin_email');
        $subject = 'SafeGuardWP - IP Address Blocked';
        $message = sprintf(
            "An IP address has been blocked due to excessive failed login attempts:\n\n" .
            "IP: %s\n" .
            "Username: %s\n" .
            "Failed Attempts: %d\n" .
            "Time: %s\n\n" .
            "This is an automated security measure taken by SafeGuardWP.",
            $ip,
            $username,
            $attempts,
            current_time('mysql')
        );

        wp_mail($admin_email, $subject, $message);
    }

    private function notify_admin_distributed_attack($username, $ip_count) {
        $admin_email = get_option('admin_email');
        $subject = 'SafeGuardWP - Distributed Attack Warning';
        $message = sprintf(
            "A potential distributed brute force attack has been detected:\n\n" .
            "Target Username: %s\n" .
            "Unique IPs: %d\n" .
            "Time: %s\n\n" .
            "Please review the security logs for more details.",
            $username,
            $ip_count,
            current_time('mysql')
        );

        wp_mail($admin_email, $subject, $message);
    }

    private function get_client_ip() {
        $ip = '';
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) // Cloudflare
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        elseif(isset($_SERVER['HTTP_X_REAL_IP'])) // X-Real-IP header
            $ip = $_SERVER['HTTP_X_REAL_IP'];
        elseif(isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // X-Forwarded-For header, use first IP
            $ip_array = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ip_array[0]);
        }
        elseif(isset($_SERVER['REMOTE_ADDR']))
            $ip = $_SERVER['REMOTE_ADDR'];

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }
}