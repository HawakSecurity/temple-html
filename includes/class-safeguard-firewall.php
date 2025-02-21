<?php
class SafeGuard_Firewall {
    private $wpdb;
    private $detection_rules = array();
    private $whitelisted_ips = array();
    private $is_development = false;
    private $waf_mode;
    private $ai_analyzer;

    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
        $this->is_development = (defined('WP_DEBUG') && WP_DEBUG);
        $this->initialize_settings();
        $this->initialize_detection_rules();

        // Initialize AI Analyzer
        require_once SAFEGUARD_PLUGIN_DIR . 'includes/class-safeguard-ai-analyzer.php';
        $this->ai_analyzer = new SafeGuard_AI_Analyzer();

        add_action('init', array($this, 'check_request'), 1);
        add_action('wp_loaded', array($this, 'cleanup_expired_bans'));

        error_log('SafeGuardWP Firewall: Initialized with mode: ' . $this->waf_mode);
    }

    private function initialize_settings() {
        // Load whitelisted IPs and WAF mode from options
        $this->whitelisted_ips = get_option('safeguard_whitelisted_ips', array('127.0.0.1', '::1'));
        $this->waf_mode = get_option('safeguard_waf_mode', 'moderate');

        error_log('SafeGuardWP Firewall Settings: Mode=' . $this->waf_mode . ', WhitelistedIPs=' . implode(',', $this->whitelisted_ips));
    }

    private function initialize_detection_rules() {
        // XSS Detection - Improved patterns with encoding detection
        $this->detection_rules['xss'] = array(
            'name' => 'XSS',
            'pattern' => '/(<script[^>]*>.*?<\/script>|javascript:|eval\s*\(|\bon[a-z]+\s*=|data:text\/html|base64|alert\s*\(|document\.cookie|<img[^>]*onerror|<iframe[^>]*src|&#x?[0-9a-f]+;|%3c%73%63%72%69%70%74|%253c%2573%2563%72%69%70%74|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\\\"|\\\\\\/|%u[0-9a-f]{4}|%[0-9a-f]{2})/is',
            'score' => $this->is_development ? 2 : 5,
        );

        // SQL Injection - Extended patterns with encoding detection
        $this->detection_rules['sqli'] = array(
            'name' => 'SQLi',
            'pattern' => '/(UNION\s+ALL\s+SELECT|DROP\s+TABLE|SELECT.*FROM|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+.*\s+SET|OR\s+1\s*=\s*1|AND\s+1\s*=\s*1|SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|%55%4e%49%4f%4e|%2575%256e%2569%256f%256e|\\x75\\x6e\\x69\\x6f\\x6e|(?:\\\\x(?:25)*(?:2[35])+)+|0x[0-9a-f]+)/is',
            'score' => $this->is_development ? 3 : 6,
        );

        // Base64 encoded payloads detection
        $this->detection_rules['base64_payload'] = array(
            'name' => 'Base64 Encoded Payload',
            'pattern' => '/((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)*(?:[A-Za-z0-9+\/]{4})+)(?:[^A-Za-z0-9+\/]|$)/i',
            'score' => $this->is_development ? 3 : 5,
        );

        // Double URL Encoding Detection
        $this->detection_rules['double_urlencode'] = array(
            'name' => 'Double URL Encoding',
            'pattern' => '/(%25(?:25)*[0-9A-Fa-f]{2}|%25[0-9A-Fa-f]{2}%25[0-9A-Fa-f]{2}|%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2})/i',
            'score' => $this->is_development ? 2 : 4,
        );

        // Remote File Inclusion - Enhanced detection with encoding
        $this->detection_rules['rfi'] = array(
            'name' => 'RFI',
            'pattern' => '/(https?:\/\/[^\s]+\?.+\.(php|asp|aspx|jsp)|php:\/\/input|expect:\/\/|data:\/\/|file:\/\/|ftp:\/\/|gopher:\/\/|phar:\/\/|%(?:25)*(?:66|70)%(?:25)*(?:74|68)%(?:25)*(?:70|61)|base64_decode\s*\([^)]*\)|eval\s*\(\s*base64_decode|data:(?:[^;]*;)*(?:\s*)?base64)/i',
            'score' => $this->is_development ? 3 : 5,
        );

        // Command Injection - More comprehensive with encoding
        $this->detection_rules['cmdi'] = array(
            'name' => 'CMDi',
            'pattern' => '/(;\s*\w+\s*[\/\\\\]|`.*`|\|\s*\w+|\&\s*\w+|\$\(.*\)|\bping\s+-[tc]\b|\bnetcat\b|\bnc\s+-[el]\b|\btelnet\b|\bcurl\s+|wget\s+|%(?:25)*(?:7c|26|3b|60)|%(?:25)*(?:2f|5c)|(?:%0D|%0A|\\r|\\n|\r|\n)+|%(?:25)*(?:70|50)%(?:25)*(?:49|69)%(?:25)*(?:4e|6e)%(?:25)*(?:47|67))/i',
            'score' => $this->is_development ? 3 : 6,
        );

        // Directory Traversal - Additional patterns with encoding
        $this->detection_rules['traversal'] = array(
            'name' => 'Directory Traversal',
            'pattern' => '/(\.\.\/|\.\.\\\|%2e%2e%2f|%2e%2e\/|\.\.\%2f|%252e%252e%252f|\.\.\%252f|\.\.\%c0\%af|\.\.\%c1\%9c|%c0%ae%c0%ae\/|\.\.\%u2215|\.\.\%u2216|\.\.\x2f|\.\.\x5c|%(?:25)*(?:2e|2E)%(?:25)*(?:2e|2E)%(?:25)*(?:2f|2F|5c|5C)|\\x2e\\x2e[\\x2f\\x5c]|%u002e%u002e%u2215)/i',
            'score' => $this->is_development ? 4 : 6,
        );

        // Remote Code Execution - Expanded patterns with encoding
        $this->detection_rules['rce'] = array(
            'name' => 'RCE',
            'pattern' => '/(system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|eval\s*\(|assert\s*\(|preg_replace.*\/e|create_function\s*\(|include\s*\(|require\s*\(|pcntl_exec\s*\(|proc_open\s*\(|popen\s*\(|%(?:25)*(?:73|53)%(?:25)*(?:59|79)%(?:25)*(?:53|73)%(?:25)*(?:54|74)%(?:25)*(?:45|65)%(?:25)*(?:4d|6d)|\\x73\\x79\\x73\\x74\\x65\\x6d)/i',
            'score' => $this->is_development ? 7 : 10,
        );

        // XML External Entity - Additional vectors with encoding
        $this->detection_rules['xxe'] = array(
            'name' => 'XXE',
            'pattern' => '/(!ENTITY.*SYSTEM|!DOCTYPE.*SYSTEM|!ENTITY.*PUBLIC|<\?xml.*version|xmlns:.*DTD|<!ENTITY.*%.*SYSTEM|<!ENTITY.*%.*PUBLIC|%(?:25)*(?:3c|3C)%(?:25)*(?:21|21)%(?:25)*(?:45|65)%(?:25)*(?:4e|6e)%(?:25)*(?:54|74)%(?:25)*(?:49|69)%(?:25)*(?:54|74)%(?:25)*(?:59|79))/i',
            'score' => $this->is_development ? 5 : 8,
        );

        // Server-Side Template Injection - Enhanced patterns with encoding
        $this->detection_rules['ssti'] = array(
            'name' => 'SSTI',
            'pattern' => '/(\{\{.*\}\}|\{\%.*\%\}|\$\{.*\}|#\{.*\}|<%.*%>|\${.*}|\$\{.*\}|@\{.*\}|\$\{\{.*\}\}|\[\[.*\]\]|%(?:25)*(?:7b|7B)%(?:25)*(?:7b|7B)|%(?:25)*(?:24|24)%(?:25)*(?:7b|7B))/i',
            'score' => $this->is_development ? 5 : 7,
        );

        // PHP Object Injection with encoding detection
        $this->detection_rules['object_injection'] = array(
            'name' => 'Object Injection',
            'pattern' => '/(O:[0-9]+:"|C:[0-9]+:"|obj|object|stdClass|__PHP_Incomplete_Class|php_uname|phpinfo|base64_decode\s*\(.*\)|serializ|%4f%3a|%43%3a|%4f%3a%64|%43%3a%64|%4F%3A%\d+%3A|%43%3A%\d+%3A)/i',
            'score' => $this->is_development ? 6 : 9,
        );

        // Null Byte Injection with various encodings
        $this->detection_rules['null_byte'] = array(
            'name' => 'Null Byte Injection',
            'pattern' => '/(%00|\\x00|\\u0000|\\0|%0|%u0000|\\x0|\\x00|\\x00\\x00|%00%00|0x00|&#0;|\\0\\0\\0|\\u0000\\u0000|\\x00\\x00\\x00|%00%00%00)/i',
            'score' => $this->is_development ? 4 : 7,
        );

        error_log('SafeGuardWP Firewall: Initialized ' . count($this->detection_rules) . ' detection rules with enhanced encoding detection');
    }

    private function get_mode_thresholds() {
        $base_thresholds = array(
            'passive' => array('warn' => 15, 'block' => 25),
            'moderate' => array('warn' => 10, 'block' => 20),
            'aggressive' => array('warn' => 5, 'block' => 15),
            'learning' => array('warn' => 10, 'block' => 20)
        );

        $mode = $this->is_development ? 'passive' : $this->waf_mode;
        if (!isset($base_thresholds[$mode])) {
            error_log("SafeGuardWP Firewall: Invalid mode '$mode', falling back to moderate");
            $mode = 'moderate';
        }

        $thresholds = $base_thresholds[$mode];
        error_log("SafeGuardWP Firewall: Using mode '$mode' with thresholds: warn={$thresholds['warn']}, block={$thresholds['block']}");
        return $thresholds;
    }

    private function get_mode_description($mode) {
        $descriptions = array(
            'passive' => 'Only logs potential threats without taking action',
            'moderate' => 'Balanced protection with moderate thresholds',
            'aggressive' => 'Strict protection with low thresholds',
            'learning' => 'Monitors and logs but does not block'
        );
        return isset($descriptions[$mode]) ? $descriptions[$mode] : 'Unknown mode';
    }

    private function should_analyze_request() {
        // Skip analysis for specific WordPress admin actions
        if (defined('DOING_AJAX') && DOING_AJAX) {
            $allowed_actions = array('heartbeat', 'autosave');
            if (isset($_REQUEST['action']) && in_array($_REQUEST['action'], $allowed_actions)) {
                error_log("SafeGuardWP Firewall: Skipping analysis for WordPress action: {$_REQUEST['action']}");
                return false;
            }
        }

        // Skip for WordPress core update processes
        if (defined('WP_INSTALLING') && WP_INSTALLING) {
            error_log('SafeGuardWP Firewall: Skipping analysis during WordPress installation/update');
            return false;
        }

        return true;
    }

    private function is_admin_user() {
        return (function_exists('current_user_can') && current_user_can('manage_options'));
    }

    public function check_request() {
        if (!$this->should_analyze_request()) {
            return;
        }

        $client_ip = $this->get_client_ip();
        error_log("SafeGuardWP Firewall: Checking request from IP: $client_ip");

        // Skip checks for whitelisted IPs
        if (in_array($client_ip, $this->whitelisted_ips)) {
            error_log("SafeGuardWP Firewall: Skipping checks for whitelisted IP: $client_ip");
            return;
        }

        // Get request data
        $request_data = $this->get_request_data();
        error_log("SafeGuardWP Firewall: Analyzing request data: " . print_r($request_data, true));

        // Adjust thresholds based on WAF mode
        $thresholds = $this->get_mode_thresholds();
        error_log("SafeGuardWP Firewall: Using thresholds - warn: {$thresholds['warn']}, block: {$thresholds['block']}");

        if ($this->is_ip_banned($client_ip)) {
            error_log("SafeGuardWP Firewall: Blocked banned IP: $client_ip");
            $this->show_block_page($client_ip, 'IP is banned', $this->get_ban_expiry($client_ip));
            return;
        }

        // Combine rule-based and AI analysis
        $request_score = $this->analyze_request($request_data);
        error_log("SafeGuardWP Firewall: Final request analysis score: $request_score");

        // Special handling for admin users
        if ($this->is_admin_user()) {
            error_log("SafeGuardWP Firewall: Admin user detected, adjusting thresholds");
            $thresholds['block'] *= 1.5; // Higher threshold for admin users
        }

        if ($request_score >= $thresholds['block'] || $this->contains_vulnerability_payload($request_data)) {
            if ($this->waf_mode !== 'learning') {
                $reason = $request_score >= $thresholds['block'] ? 'Critical security threshold exceeded' : 'Vulnerability exploit attempt detected';
                error_log("SafeGuardWP Firewall: Blocking IP $client_ip - $reason");
                
                // Check if IP is already banned
                $existing_ban = $this->wpdb->get_row($this->wpdb->prepare(
                    "SELECT * FROM {$this->wpdb->prefix}safeguard_blocked_ips WHERE ip_address = %s",
                    $client_ip
                ));

                $permanent_ban = get_option('safeguard_permanent_ban_attacks', false) && $request_score >= $thresholds['block'];
                $ban_count = $existing_ban ? $existing_ban->ban_count + 1 : 1;
                
                if ($permanent_ban) {
                    $blocked_until = '2099-12-31 23:59:59'; // Effectively permanent
                } else {
                    $ban_days = get_option('safeguard_ban_duration', 30);
                    // For repeat offenders, increase duration exponentially
                    $ban_days = min($ban_days * pow(2, $ban_count - 1), 365); // Cap at 1 year
                    $blocked_until = date('Y-m-d H:i:s', strtotime("+{$ban_days} days"));
                }
                
                // Force immediate ban
                $this->wpdb->query($this->wpdb->prepare(
                    "INSERT INTO {$this->wpdb->prefix}safeguard_blocked_ips 
                    (ip_address, reason, blocked_until, ban_count, first_ban_date, last_ban_date) 
                    VALUES (%s, %s, %s, %d, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    blocked_until = VALUES(blocked_until),
                    ban_count = ban_count + 1,
                    last_ban_date = VALUES(last_ban_date)",
                    $client_ip,
                    $reason,
                    date('Y-m-d H:i:s', strtotime('+24 hours')),
                    1,
                    current_time('mysql'),
                    current_time('mysql')
                ));
                
                $this->show_block_page($client_ip, $reason, date('Y-m-d H:i:s', strtotime('+24 hours')));
            } else {
                error_log("SafeGuardWP Firewall Learning Mode: Would have blocked IP $client_ip");
            }
        } elseif ($request_score >= $thresholds['warn']) {
            error_log("SafeGuardWP Firewall: Warning for IP $client_ip - Score: $request_score");
            $this->log_attack('Suspicious activity detected', $request_score);
            if ($this->waf_mode === 'aggressive') {
                $this->show_warning_page($client_ip);
            }
        }
    }

    private function get_request_data() {
        $headers = $this->get_request_headers();
        $cookies = is_array($_COOKIE) ? $_COOKIE : array();

        return array(
            'ip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
            'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '',
            'uri' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '',
            'query' => isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '',
            'post' => file_get_contents('php://input'),
            'headers' => is_array($headers) ? $headers : array(),
            'cookies' => $cookies,
            'files' => is_array($_FILES) ? $_FILES : array(),
        );
    }

    private function analyze_request($request_data) {
        $score = 0;
        error_log('SafeGuardWP Firewall: Starting request analysis');

        // Get AI analysis result
        $ai_result = $this->ai_analyzer->analyze_request($request_data);
        error_log('SafeGuardWP Firewall: AI Analysis result - ' . print_r($ai_result, true));

        if ($ai_result !== false) {
            // Add AI confidence score to total
            $score += ($ai_result['confidence'] * 10); // Scale confidence to match our scoring
            error_log("SafeGuardWP Firewall: AI Score contribution: " . ($ai_result['confidence'] * 10));

            // Log AI detection if it's a threat
            if ($ai_result['is_threat']) {
                $this->log_attack(
                    sprintf('AI detected %s attack', $ai_result['type']),
                    $score,
                    $ai_result['details']
                );
            }
        }

        // Perform rule-based analysis on each request component
        foreach ($request_data as $source => $data) {
            if (!is_string($data)) {
                if (is_array($data)) {
                    // Analyze array values recursively
                    foreach ($data as $key => $value) {
                        if (is_string($value)) {
                            $rule_score = $this->check_payload($value, "$source[$key]");
                            $score += $rule_score;
                            error_log("SafeGuardWP Firewall: Rule-based score for $source[$key]: $rule_score");
                        }
                    }
                }
                continue;
            }
            $rule_score = $this->check_payload($data, $source);
            $score += $rule_score;
            error_log("SafeGuardWP Firewall: Rule-based score for $source: $rule_score");
        }

        error_log("SafeGuardWP Firewall: Final analysis score: $score");
        return $score;
    }

    private function check_payload($value, $source) {
        if (empty($value)) return 0;

        if (is_array($value)) {
            $score = 0;
            foreach ($value as $key => $val) {
                if (is_array($val)) {
                    foreach ($val as $subval) {
                        $score += $this->check_single_payload($subval, $source . '[' . $key . ']');
                    }
                } else {
                    $score += $this->check_single_payload($val, $source . '[' . $key . ']');
                }
            }
            return $score;
        } elseif (is_string($value)) {
            return $this->check_single_payload($value, $source);
        }

        return 0;
    }

    private function check_single_payload($value, $source) {
        if (!is_string($value)) return 0;

        // Suppress warnings for header checks
        error_reporting(error_reporting() & ~E_NOTICE & ~E_WARNING);

        $score = 0;
        foreach ($this->detection_rules as $rule) {
            try {
                // Try to decode potential encoded content
                $decoded_value = $value;

                // URL Decode (multiple passes for multiple encodings)
                for ($i = 0; $i < 3; $i++) {
                    $temp = urldecode($decoded_value);
                    if ($temp === $decoded_value) break;
                    $decoded_value = $temp;
                }

                // Base64 Decode Attempt (if it looks like base64)
                if (preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $decoded_value)) {
                    $temp = base64_decode($decoded_value, true);
                    if ($temp !== false) {
                        $decoded_value = $temp;
                    }
                }

                // Check both original and decoded values
                if (@preg_match($rule['pattern'], $value) || @preg_match($rule['pattern'], $decoded_value)) {
                    $score += $rule['score'];
                    error_log("SafeGuardWP Firewall: Detected {$rule['name']} in $source - Score: {$rule['score']}");
                    error_log("SafeGuardWP Firewall: Matched value: " . substr($value, 0, 100) . "...");
                    $this->log_attack(
                        sprintf('Detected %s in %s', $rule['name'], $source),
                        $rule['score'],
                        array(
                            'pattern' => $rule['pattern'],
                            'matched_value' => substr($value, 0, 255),
                            'decoded_value' => substr($decoded_value, 0, 255),
                            'source' => $source
                        )
                    );
                }
            } catch (Exception $e) {
                error_log("SafeGuardWP Firewall Error: Regex error in {$rule['name']} - " . $e->getMessage());
            }
        }
        return $score;
    }

    private function show_warning_page($ip) {
        status_header(403);
        include(SAFEGUARD_PLUGIN_DIR . 'templates/warning-page.php');
        exit;
    }

    private function get_ban_expiry($ip) {
        $result = $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT blocked_until FROM {$this->wpdb->prefix}safeguard_blocked_ips WHERE ip_address = %s",
            $ip
        ));
        return $result ?: date('Y-m-d H:i:s', strtotime('+1 hour'));
    }

    private function is_ip_banned($ip) {
        $table_name = $this->wpdb->prefix . 'safeguard_blocked_ips';

        $banned = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT * FROM $table_name WHERE ip_address = %s AND blocked_until > NOW()",
            $ip
        ));

        return $banned !== null;
    }

    private function ban_ip($ip, $reason) {
        $table_name = $this->wpdb->prefix . 'safeguard_blocked_ips';

        // Get current ban count and details
        $existing_ban = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT ban_count, first_ban_date FROM $table_name WHERE ip_address = %s",
            $ip
        ));

        $ban_count = $existing_ban ? $existing_ban->ban_count + 1 : 1;
        $first_ban_date = $existing_ban ? $existing_ban->first_ban_date : current_time('mysql');

        // Ban duration increases with each ban: 1h, 2h, 4h, 8h, etc. up to 1 week
        $ban_hours = min(pow(2, $ban_count - 1), 168); // Cap at 168 hours (1 week)
        $blocked_until = date('Y-m-d H:i:s', strtotime("+{$ban_hours} hours"));

        // Use REPLACE INTO to handle duplicate IPs
        $this->wpdb->query($this->wpdb->prepare(
            "INSERT INTO $table_name 
            (ip_address, reason, blocked_until, ban_count, first_ban_date, last_ban_date) 
            VALUES (%s, %s, %s, %d, %s, %s)
            ON DUPLICATE KEY UPDATE 
            reason = VALUES(reason),
            blocked_until = VALUES(blocked_until),
            ban_count = ban_count + 1,
            last_ban_date = VALUES(last_ban_date)",
            $ip,
            $reason,
            $blocked_until,
            $ban_count,
            $first_ban_date,
            current_time('mysql')
        ));

        $this->notify_admin_ip_ban($ip, $reason, $ban_hours);
        $this->show_block_page($ip, $reason, $blocked_until);
    }

    private function show_block_page($ip, $reason, $blocked_until) {
        status_header(403);
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Blocked - Security Alert</title>
            <style>
                body {
                    margin: 0;
                    padding: 0;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    background: #f5f6fa;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                    color: #2f3640;
                }
                .block-container {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 20px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 600px;
                    width: 90%;
                }
                .shield-icon {
                    width: 120px;
                    height: 120px;
                    margin-bottom: 20px;
                    animation: pulse 2s infinite;
                }
                @keyframes pulse {
                    0% { transform: scale(1); }
                    50% { transform: scale(1.05); }
                    100% { transform: scale(1); }
                }
                h1 {
                    color: #e74c3c;
                    margin: 0 0 20px;
                    font-size: 28px;
                }
                .info-box {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                    text-align: left;
                }
                .info-item {
                    margin: 10px 0;
                    display: flex;
                    align-items: center;
                }
                .info-label {
                    font-weight: 600;
                    width: 140px;
                }
                .timer {
                    font-size: 24px;
                    font-weight: bold;
                    color: #e74c3c;
                    margin: 20px 0;
                }
                .unblock-info {
                    color: #7f8c8d;
                    font-size: 14px;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="block-container">
                <svg class="shield-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#e74c3c" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M12 8v4M12 16h.01" stroke-linecap="round"/>
                </svg>

                <h1>Access Blocked</h1>
                <p>Our security system has detected suspicious activity from your IP address.</p>

                <div class="info-box">
                    <div class="info-item">
                        <span class="info-label">IP Address:</span>
                        <span><?php echo wp_kses_post($ip); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Reason:</span>
                        <span><?php echo wp_kses_post($reason); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Blocked Until:</span>
                        <span class="timer" id="unblock-timer">
                            <?php echo wp_kses_post(human_time_diff(time(), strtotime($blocked_until))); ?>
                        </span>
                    </div>
                </div>

                <p class="unblock-info">
                    If you believe this is a mistake, please contact the site administrator.<br>
                    This is an automated security measure to protect against malicious activity.
                </p>
            </div>

            <script>
            function updateTimer() {
                const unblockTime = new Date('<?php echo esc_js($blocked_until); ?>').getTime();
                const timer = document.getElementById('unblock-timer');

                setInterval(() => {
                    const now = new Date().getTime();
                    const distance = unblockTime - now;

                    if (distance <= 0) {
                        timer.innerHTML = 'Block expired. Please refresh the page.';
                        return;
                    }

                    const hours = Math.floor(distance / (1000 * 60 * 60));
                    const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                    const seconds = Math.floor((distance % (1000 * 60)) / 1000);

                    timer.innerHTML = `${hours}h ${minutes}m ${seconds}s`;
                }, 1000);
            }
            updateTimer();
            </script>
        </body>
        </html>
        <?php
        exit;
    }

    public function cleanup_expired_bans() {
        $table_name = $this->wpdb->prefix . 'safeguard_blocked_ips';
        $this->wpdb->query("DELETE FROM $table_name WHERE blocked_until <= NOW()");
    }

    private function log_attack($description, $score, $additional_data = array()) {
        $table_name = $this->wpdb->prefix . 'safeguard_logs';
        $ip = $this->get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        
        // Get all headers
        $headers = $this->get_request_headers();
        $headers_string = '';
        foreach ($headers as $key => $value) {
            $headers_string .= "$key: $value\n";
        }

        // Get request payload
        $payload = file_get_contents('php://input');
        if (empty($payload)) {
            $payload = http_build_query($_POST);
        }

        $attack_data = array_merge($additional_data, array(
            'headers' => $headers_string,
            'payload' => $payload,
            'query_string' => isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '',
            'server_protocol' => isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : '',
            'remote_port' => isset($_SERVER['REMOTE_PORT']) ? $_SERVER['REMOTE_PORT'] : '',
            'request_time' => isset($_SERVER['REQUEST_TIME']) ? date('Y-m-d H:i:s', $_SERVER['REQUEST_TIME']) : ''
        ));

        $this->wpdb->insert(
            $table_name,
            array(
                'event_type' => 'attack_detected',
                'event_description' => $description,
                'ip_address' => $ip,
                'user_agent' => $user_agent,
                'severity_score' => $score,
                'request_uri' => $_SERVER['REQUEST_URI'],
                'request_method' => $_SERVER['REQUEST_METHOD'],
                'additional_data' => wp_json_encode($attack_data),
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s')
        );
    }

    private function notify_admin_ip_ban($ip, $reason, $ban_hours) {
        $admin_email = get_option('admin_email');
        $subject = 'SafeGuardWP - IP Address Banned';
        $message = sprintf(
            "An IP address has been banned due to malicious activity:\n\n" .
            "IP: %s\n" .
            "Reason: %s\n" .
            "Ban Duration: %d hours\n\n" .
            "This is an automated security measure taken by SafeGuardWP.",
            $ip,
            $reason,
            $ban_hours
        );

        wp_mail($admin_email, $subject, $message);
    }

    private function get_request_headers() {
        if (function_exists('getallheaders')) {
            return getallheaders();
        }

        $headers = array();
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) === 'HTTP_') {
                $header = str_replace(
                    ' ',
                    '-',
                    ucwords(strtolower(str_replace('_', ' ', substr($name, 5))))
                );
                $headers[$header] = is_array($value) ? implode(', ', $value) : $value;
            } elseif (in_array($name, array('CONTENT_TYPE', 'CONTENT_LENGTH'))) {
                $header = str_replace('_', '-', $name);
                $headers[$header] = $value;
            }
        }
        return $headers;
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
private function contains_vulnerability_payload($request_data) {
        $vulnerability_patterns = array(
            '/(?:<|%3c).*(?:>|%3e)/i',  // Basic XSS
            '/(?:union|select|insert|update|delete)\s+.*(?:from|into|where)/i',  // SQL Injection
            '/\.\.(?:\/|\\|%2f|%5c)/i',  // Path Traversal
            '/(?:eval|system|exec|shell_exec|passthru)\s*\(/i',  // Code Injection
            '/(?:\/etc\/passwd|\/etc\/shadow|c:\\boot\.ini)/i',  // Sensitive File Access
            '/(?:\$\_POST|\$\_GET|\$\_REQUEST|\$\_SERVER|\$\_FILES)\s*\[/i'  // PHP Object Injection
        );

        foreach ($request_data as $data) {
            if (is_string($data)) {
                foreach ($vulnerability_patterns as $pattern) {
                    if (preg_match($pattern, $data)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}