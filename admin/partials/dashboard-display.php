<?php
if (!defined('ABSPATH')) {
    exit;
}

global $wpdb;

// Get security statistics
$total_attacks = $wpdb->get_var("
    SELECT COUNT(*) 
    FROM {$wpdb->prefix}safeguard_logs 
    WHERE event_type = 'attack_detected'
");

$critical_attacks = $wpdb->get_var("
    SELECT COUNT(*) 
    FROM {$wpdb->prefix}safeguard_logs 
    WHERE event_type = 'attack_detected' 
    AND severity_score >= 8
");

$banned_ips = $wpdb->get_var("
    SELECT COUNT(*) 
    FROM {$wpdb->prefix}safeguard_blocked_ips 
    WHERE blocked_until > NOW()
");

$file_changes = $wpdb->get_var("
    SELECT COUNT(*) 
    FROM {$wpdb->prefix}safeguard_file_changes 
    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
");

// Get recent security events with more details
$recent_attacks = $wpdb->get_results("
    SELECT l.*, 
           COALESCE(l.event_description, 'Unknown Attack') as attack_description,
           COALESCE(l.event_type, 'unknown') as attack_type,
           COALESCE(l.severity_score, 5) as severity,
           COALESCE(l.additional_data, '{}') as attack_details
    FROM {$wpdb->prefix}safeguard_logs l
    WHERE l.event_type = 'attack_detected'
    ORDER BY l.created_at DESC 
    LIMIT 10
");

// Get attack statistics for chart
$attack_stats = $wpdb->get_results("
    SELECT 
        DATE(created_at) as date,
        COUNT(*) as total_attacks,
        SUM(CASE WHEN severity_score >= 8 THEN 1 ELSE 0 END) as critical_attacks
    FROM {$wpdb->prefix}safeguard_logs 
    WHERE event_type = 'attack_detected'
    AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    GROUP BY DATE(created_at)
    ORDER BY date ASC
");

// Prepare chart data
$dates = array();
$attack_data = array(
    'total' => array(),
    'critical' => array()
);

for ($i = 6; $i >= 0; $i--) {
    $date = date('Y-m-d', strtotime("-$i days"));
    $dates[] = date('M d', strtotime($date));
    $attack_data['total'][] = 0;
    $attack_data['critical'][] = 0;

    foreach ($attack_stats as $stat) {
        if ($stat->date == $date) {
            $attack_data['total'][6-$i] = (int)$stat->total_attacks;
            $attack_data['critical'][6-$i] = (int)$stat->critical_attacks;
        }
    }
}

// Helper function to format attack description
function format_attack_description($attack) {
    $details = json_decode($attack->attack_details, true) ?: array();
    $type = isset($details['type']) ? esc_html($details['type']) : 'Unknown';
    $method = isset($details['method']) ? esc_html($details['method']) : '';
    $uri = isset($details['uri']) ? esc_html($details['uri']) : '';

    if ($attack->attack_description !== 'Unknown Attack') {
        return esc_html($attack->attack_description);
    }

    return sprintf(
        '%s Attack via %s on %s',
        $type,
        $method,
        $uri
    );
}

// Get top attacked URLs with attack patterns
$top_urls = $wpdb->get_results("
    SELECT request_uri, 
           COUNT(*) as attack_count,
           GROUP_CONCAT(DISTINCT event_type) as attack_types
    FROM {$wpdb->prefix}safeguard_logs
    WHERE event_type = 'attack_detected'
    GROUP BY request_uri
    ORDER BY attack_count DESC
    LIMIT 5
");

// Get recent file changes
$recent_changes = $wpdb->get_results("
    SELECT file_path, change_type, detected_at 
    FROM {$wpdb->prefix}safeguard_file_changes 
    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ORDER BY detected_at DESC 
    LIMIT 5
");

// If no results, provide empty array
if (!$recent_changes) {
    $recent_changes = array();
}
?>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<div class="wrap safeguard-wrap">
    <div class="safeguard-header">
        <h1>
            <i class="dashicons dashicons-shield"></i> 
            SafeGuardWP Security Dashboard
        </h1>
    </div>

    <!-- Navigation Tabs -->
    <div class="safeguard-tabs">
        <a href="#dashboard" class="safeguard-tab-link active" data-tab="dashboard">Dashboard</a>
        <a href="#firewall" class="safeguard-tab-link" data-tab="firewall">Firewall</a>
        <a href="#file-monitor" class="safeguard-tab-link" data-tab="file-monitor">File Monitor</a>
        <a href="#blocked-ips" class="safeguard-tab-link" data-tab="blocked-ips">Blocked IPs</a>
        <a href="#settings" class="safeguard-tab-link" data-tab="settings">Settings</a>
    </div>

    <!-- Dashboard Tab Content -->
    <div id="dashboard" class="safeguard-tab-content active">
        <!-- Security Score -->
        <div class="safeguard-security-score">
            <div class="score-circle">
                <?php
                $security_score = 100;
                // Calculate security score based on enabled features and settings
                if (!get_option('safeguard_2fa_enabled', false)) $security_score -= 20;
                if (!get_option('safeguard_file_monitoring', true)) $security_score -= 15;
                if (!get_option('safeguard_malware_scanning', true)) $security_score -= 15;
                if (get_option('safeguard_login_attempts', 5) > 5) $security_score -= 10;
                ?>
                <span class="score-number"><?php echo esc_html($security_score); ?></span>
                <span class="score-label">Security Score</span>
            </div>
        </div>

        <!-- Security Statistics -->
        <div class="safeguard-stats">
            <div class="safeguard-stat-box">
                <div class="stat-icon"><i class="dashicons dashicons-shield-alt"></i></div>
                <div class="safeguard-stat-number"><?php echo esc_html($total_attacks); ?></div>
                <div class="safeguard-stat-label">Total Attacks Blocked</div>
            </div>
            <div class="safeguard-stat-box critical">
                <div class="stat-icon"><i class="dashicons dashicons-warning"></i></div>
                <div class="safeguard-stat-number"><?php echo esc_html($critical_attacks); ?></div>
                <div class="safeguard-stat-label">Critical Attacks</div>
            </div>
            <div class="safeguard-stat-box banned">
                <div class="stat-icon"><i class="dashicons dashicons-dismiss"></i></div>
                <div class="safeguard-stat-number"><?php echo esc_html($banned_ips); ?></div>
                <div class="safeguard-stat-label">Currently Banned IPs</div>
            </div>
            <div class="safeguard-stat-box files">
                <div class="stat-icon"><i class="dashicons dashicons-media-text"></i></div>
                <div class="safeguard-stat-number"><?php echo esc_html($file_changes); ?></div>
                <div class="safeguard-stat-label">File Changes (24h)</div>
            </div>
        </div>

        <!-- Recent Security Events -->
        <div class="safeguard-card">
            <h3>Recent Security Events</h3>
            <table class="safeguard-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Attack Type</th>
                        <th>IP Address</th>
                        <th>Severity</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($recent_attacks as $attack): ?>
                    <tr>
                        <td><?php echo esc_html(human_time_diff(strtotime($attack->created_at), current_time('timestamp'))); ?> ago</td>
                        <td><?php echo format_attack_description($attack); ?></td>
                        <td>
                            <?php echo esc_html($attack->ip_address); ?>
                            <?php if (isset($attack->country)): ?>
                                <span class="country-flag" title="<?php echo esc_attr($attack->country); ?>">
                                    <?php echo esc_html($attack->country); ?>
                                </span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <span class="severity-badge severity-<?php echo esc_attr($attack->severity >= 8 ? 'high' : ($attack->severity >= 5 ? 'medium' : 'low')); ?>">
                                <?php echo esc_html($attack->severity); ?>
                            </span>
                        </td>
                        <td>
                            <button class="button button-small view-details" data-attack-id="<?php echo esc_attr($attack->id); ?>">
                                Details
                            </button>
                            <?php if (!isset($attack->blocked) || !$attack->blocked): ?>
                            <button class="button button-small button-link-delete block-ip" data-ip="<?php echo esc_attr($attack->ip_address); ?>">
                                Block IP
                            </button>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- Attack Details Modal -->
        <div id="attack-details-modal" class="safeguard-modal">
            <div class="safeguard-modal-content">
                <span class="close">&times;</span>
                <h3>Attack Details</h3>
                <div id="attack-details-content"></div>
            </div>
        </div>

        <!-- Attack Trends Chart -->
        <div class="safeguard-card">
            <h3>Attack Trends (Last 7 Days)</h3>
            <canvas id="attack-trends-chart"></canvas>
        </div>

        <div class="safeguard-row">
            <!-- Most Attacked URLs -->
            <div class="safeguard-column">
                <div class="safeguard-card">
                    <h3>Most Targeted URLs</h3>
                    <table class="safeguard-table">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Attack Count</th>
                                <th>Attack Types</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($top_urls as $url): ?>
                            <tr>
                                <td><?php echo esc_html($url->request_uri); ?></td>
                                <td><?php echo esc_html($url->attack_count); ?></td>
                                <td><?php echo esc_html($url->attack_types); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Recent File Changes -->
                <div class="safeguard-card">
                    <h3>Recent File Changes</h3>
                    <table class="safeguard-table">
                        <thead>
                            <tr>
                                <th>File</th>
                                <th>Change Type</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recent_changes as $change): ?>
                            <tr>
                                <td><?php echo esc_html(basename($change->file_path)); ?></td>
                                <td>
                                    <span class="change-type-badge change-<?php echo esc_attr($change->change_type); ?>">
                                        <?php echo esc_html(ucfirst($change->change_type)); ?>
                                    </span>
                                </td>
                                <td><?php echo esc_html(human_time_diff(strtotime($change->detected_at), current_time('timestamp'))); ?> ago</td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Firewall Tab Content -->
    <div id="firewall" class="safeguard-tab-content">
        <div class="safeguard-card">
            <h3>Firewall Settings</h3>
            <form id="firewall-settings-form" class="safeguard-form">
                <div class="safeguard-form-group">
                    <label for="waf_mode">Web Application Firewall Mode</label>
                    <select id="waf_mode" name="waf_mode">
                        <option value="learning" <?php selected(get_option('safeguard_waf_mode'), 'learning'); ?>>Learning Mode</option>
                        <option value="passive" <?php selected(get_option('safeguard_waf_mode'), 'passive'); ?>>Passive Mode</option>
                        <option value="moderate" <?php selected(get_option('safeguard_waf_mode'), 'moderate'); ?>>Moderate Protection</option>
                        <option value="aggressive" <?php selected(get_option('safeguard_waf_mode'), 'aggressive'); ?>>Aggressive Protection</option>
                    </select>
                </div>
                <div class="safeguard-form-group">
                    <label for="block_threshold">Attack Block Threshold</label>
                    <input type="number" id="block_threshold" name="block_threshold" 
                           value="<?php echo esc_attr(get_option('safeguard_block_threshold', 20)); ?>" 
                           min="10" max="50">
                </div>
                <button type="submit" class="safeguard-submit-button">Save Firewall Settings</button>
            </form>
        </div>
    </div>

    <!-- File Monitor Tab Content -->
    <div id="file-monitor" class="safeguard-tab-content">
        <div class="safeguard-card">
            <h3>File Monitoring Settings</h3>
            <form id="file-monitor-settings-form" class="safeguard-form">
                <div class="safeguard-form-group">
                    <label>
                        <input type="checkbox" name="enable_file_monitoring" 
                               <?php checked(get_option('safeguard_file_monitoring'), true); ?>>
                        Enable File Change Detection
                    </label>
                </div>
                <div class="safeguard-form-group">
                    <label>Monitored Directories</label>
                    <textarea name="monitored_directories" rows="4" class="large-text"><?php 
                        echo esc_textarea(get_option('safeguard_monitored_directories', 'wp-admin/
wp-includes/
wp-content/themes/
wp-content/plugins/')); 
                    ?></textarea>
                </div>
                <button type="submit" class="safeguard-submit-button">Save Monitoring Settings</button>
            </form>
        </div>
    </div>

    <!-- Blocked IPs Tab Content -->
    <div id="blocked-ips" class="safeguard-tab-content">
        <div class="safeguard-card">
            <h3>Currently Blocked IP Addresses</h3>
            <?php
            $blocked_ips = $wpdb->get_results("
                SELECT * FROM {$wpdb->prefix}safeguard_blocked_ips 
                WHERE blocked_until > NOW()
                ORDER BY last_ban_date DESC
            ");
            ?>
            <table class="safeguard-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Reason</th>
                        <th>Blocked Until</th>
                        <th>Ban Count</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($blocked_ips as $ip): ?>
                    <tr>
                        <td><?php echo esc_html($ip->ip_address); ?></td>
                        <td><?php echo esc_html($ip->reason); ?></td>
                        <td><?php echo esc_html(human_time_diff(time(), strtotime($ip->blocked_until))); ?> remaining</td>
                        <td><?php echo esc_html($ip->ban_count); ?></td>
                        <td>
                            <button class="button button-small unblock-ip" data-ip="<?php echo esc_attr($ip->ip_address); ?>">
                                Unblock
                            </button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Settings Tab Content -->
    <div id="settings" class="safeguard-tab-content">
        <div class="safeguard-card">
            <h3>General Security Settings</h3>
            <form id="general-settings-form" class="safeguard-form">
                <div class="safeguard-form-group">
                    <label>
                        <input type="checkbox" name="enable_2fa" 
                               <?php checked(get_option('safeguard_2fa_enabled'), true); ?>>
                        Enable Two-Factor Authentication
                    </label>
                </div>
                <div class="safeguard-form-group">
                    <label for="login_attempts">Max Login Attempts</label>
                    <input type="number" id="login_attempts" name="login_attempts" 
                           value="<?php echo esc_attr(get_option('safeguard_login_attempts', 5)); ?>" 
                           min="3" max="10">
                </div>
                <div class="safeguard-form-group">
                    <label for="ban_duration">Default Ban Duration (days)</label>
                    <input type="number" id="ban_duration" name="ban_duration" 
                           value="<?php echo esc_attr(get_option('safeguard_ban_duration', 30)); ?>" 
                           min="1" max="365">
                    <p class="description">Set the default duration for IP bans in days. Permanent bans can be set manually.</p>
                </div>
                <div class="safeguard-form-group">
                    <label>
                        <input type="checkbox" name="permanent_ban_attacks" 
                               <?php checked(get_option('safeguard_permanent_ban_attacks'), true); ?>>
                        Permanently ban IPs for serious attacks
                    </label>
                </div>
                <div class="safeguard-form-group">
                    <label>
                        <input type="checkbox" name="enable_country_blocking" 
                               <?php checked(get_option('safeguard_country_blocking'), true); ?>>
                        Enable Country-based Blocking
                    </label>
                </div>
                <div class="safeguard-form-group">
                    <label>
                        <input type="checkbox" name="enable_malware_scanning" 
                               <?php checked(get_option('safeguard_malware_scanning'), true); ?>>
                        Enable Malware Scanning
                    </label>
                </div>
                <button type="submit" class="safeguard-submit-button">Save Settings</button>
            </form>
        </div>

        <!-- Email Notifications -->
        <div class="safeguard-card">
            <h3>Email Notifications</h3>
            <form id="notification-settings-form" class="safeguard-form">
                <?php wp_nonce_field('safeguard_notification_nonce', 'safeguard_notification_nonce'); ?>
                <div class="safeguard-form-group">
                    <label>
                        <input type="checkbox" name="enable_attack_notifications" 
                               <?php checked(get_option('safeguard_attack_notifications'), true); ?>>
                        Receive Critical Attack Notifications
                    </label>
                </div>
                <div class="safeguard-form-group">
                    <label>
                        <input type="checkbox" name="enable_file_notifications" 
                               <?php checked(get_option('safeguard_file_notifications'), true); ?>>
                        Receive File Change Notifications
                    </label>
                </div>
                <div class="safeguard-form-group">
                    <label for="notification_email">Notification Email</label>
                    <input type="email" id="notification_email" name="notification_email" 
                           value="<?php echo esc_attr(get_option('safeguard_notification_email', get_option('admin_email'))); ?>">
                </div>
                <button type="submit" class="safeguard-submit-button">Save Notification Settings</button>
                <div class="safeguard-form-message"></div>
            </form>
        </div>
    </div>

    <script>
        jQuery(document).ready(function($) {
            // Initialize Chart.js for attack trends
            var ctx = document.getElementById('attack-trends-chart').getContext('2d');
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: <?php echo json_encode($dates); ?>,
                    datasets: [{
                        label: 'Total Attacks',
                        data: <?php echo json_encode($attack_data['total']); ?>,
                        borderColor: 'rgb(54, 162, 235)',
                        backgroundColor: 'rgba(54, 162, 235, 0.1)',
                        fill: true
                    }, {
                        label: 'Critical Attacks',
                        data: <?php echo json_encode($attack_data['critical']); ?>,
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.1)',
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Attacks'
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top'
                        },
                        title: {
                            display: true,
                            text: 'Attack Trends Over Time'
                        }
                    }
                }
            });

            // Tabbed Navigation
            $('.safeguard-tab-link').click(function(e) {
                e.preventDefault();
                var tab = $(this).data('tab');
                $('.safeguard-tab-link').removeClass('active');
                $(this).addClass('active');
                $('.safeguard-tab-content').removeClass('active');
                $('#' + tab).addClass('active');
            });
        });
    </script>
</div>