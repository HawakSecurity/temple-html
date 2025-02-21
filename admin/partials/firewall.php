<?php
if (!defined('ABSPATH')) {
    exit;
}

global $wpdb;

// Get firewall statistics
$blocked_requests = $wpdb->get_var("
    SELECT COUNT(*) 
    FROM {$wpdb->prefix}safeguard_logs 
    WHERE event_type = 'attack_detected'
    AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
");

$custom_rules = get_option('safeguard_custom_rules', array());
$waf_mode = get_option('safeguard_waf_mode', 'aggressive');

// Get attack patterns for today vs yesterday
$today_attacks = $wpdb->get_results("
    SELECT HOUR(created_at) as hour, COUNT(*) as count
    FROM {$wpdb->prefix}safeguard_logs
    WHERE event_type = 'attack_detected'
    AND DATE(created_at) = CURDATE()
    GROUP BY HOUR(created_at)
    ORDER BY hour ASC
");

$yesterday_attacks = $wpdb->get_results("
    SELECT HOUR(created_at) as hour, COUNT(*) as count
    FROM {$wpdb->prefix}safeguard_logs
    WHERE event_type = 'attack_detected'
    AND DATE(created_at) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
    GROUP BY HOUR(created_at)
    ORDER BY hour ASC
");

// Prepare data for hourly comparison chart
$hourly_data = array(
    'today' => array_fill(0, 24, 0),
    'yesterday' => array_fill(0, 24, 0)
);

foreach ($today_attacks as $attack) {
    $hourly_data['today'][$attack->hour] = (int)$attack->count;
}

foreach ($yesterday_attacks as $attack) {
    $hourly_data['yesterday'][$attack->hour] = (int)$attack->count;
}

// Get attack types distribution
$attack_types = $wpdb->get_results("
    SELECT attack_type, COUNT(*) as count
    FROM {$wpdb->prefix}safeguard_logs
    WHERE event_type = 'attack_detected'
    AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    GROUP BY attack_type
    ORDER BY count DESC
    LIMIT 5
");
?>

<div class="safeguard-tab-content" id="firewall">
    <!-- Firewall Mode Selection -->
    <div class="safeguard-row">
        <div class="safeguard-column">
            <div class="safeguard-card">
                <h3>Firewall Mode</h3>
                <form method="post" action="" class="safeguard-form">
                    <?php wp_nonce_field('safeguard_firewall_settings'); ?>
                    <div class="safeguard-form-group">
                        <select name="waf_mode" id="waf_mode">
                            <option value="learning" <?php selected($waf_mode, 'learning'); ?>>Learning Mode</option>
                            <option value="passive" <?php selected($waf_mode, 'passive'); ?>>Passive Mode (Log Only)</option>
                            <option value="moderate" <?php selected($waf_mode, 'moderate'); ?>>Moderate Protection</option>
                            <option value="aggressive" <?php selected($waf_mode, 'aggressive'); ?>>Aggressive Protection</option>
                        </select>
                    </div>
                    <button type="submit" name="save_firewall_mode" class="button button-primary">Save Mode</button>
                </form>
            </div>

            <div class="safeguard-card">
                <h3>Add Custom Rule</h3>
                <form method="post" action="" class="safeguard-form">
                    <?php wp_nonce_field('safeguard_add_rule'); ?>
                    <div class="safeguard-form-group">
                        <label for="rule_name">Rule Name</label>
                        <input type="text" name="rule_name" id="rule_name" required>
                    </div>
                    <div class="safeguard-form-group">
                        <label for="rule_type">Rule Type</label>
                        <select name="rule_type" id="rule_type">
                            <option value="regex">Regular Expression</option>
                            <option value="exact">Exact Match</option>
                            <option value="contains">Contains</option>
                        </select>
                    </div>
                    <div class="safeguard-form-group">
                        <label for="rule_pattern">Pattern</label>
                        <input type="text" name="rule_pattern" id="rule_pattern" required>
                        <p class="description">For regex, use PHP compatible regular expressions. For exact/contains, enter the string to match.</p>
                    </div>
                    <div class="safeguard-form-group">
                        <label for="rule_action">Action</label>
                        <select name="rule_action" id="rule_action">
                            <option value="block">Block Request</option>
                            <option value="log">Log Only</option>
                            <option value="challenge">Challenge User</option>
                        </select>
                    </div>
                    <div class="safeguard-form-group">
                        <label for="severity">Severity Score (1-10)</label>
                        <input type="number" name="severity" id="severity" min="1" max="10" value="5">
                    </div>
                    <button type="submit" name="add_custom_rule" class="button button-primary">Add Rule</button>
                </form>
            </div>
        </div>

        <div class="safeguard-column">
            <!-- Attack Statistics -->
            <div class="safeguard-card">
                <h3>Attack Statistics (24h)</h3>
                <div class="safeguard-stat-box">
                    <div class="stat-icon"><i class="dashicons dashicons-shield"></i></div>
                    <div class="safeguard-stat-number"><?php echo esc_html($blocked_requests); ?></div>
                    <div class="safeguard-stat-label">Blocked Requests</div>
                </div>
                
                <div class="attack-chart-container">
                    <canvas id="attack-comparison-chart"></canvas>
                </div>
            </div>

            <!-- Attack Types Distribution -->
            <div class="safeguard-card">
                <h3>Attack Types (Last 7 Days)</h3>
                <div class="attack-types-chart-container">
                    <canvas id="attack-types-chart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <!-- Custom Rules List -->
    <div class="safeguard-card">
        <h3>Custom Rules</h3>
        <table class="safeguard-table">
            <thead>
                <tr>
                    <th>Rule Name</th>
                    <th>Type</th>
                    <th>Pattern</th>
                    <th>Action</th>
                    <th>Severity</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($custom_rules as $rule_id => $rule): ?>
                <tr>
                    <td><?php echo esc_html($rule['name']); ?></td>
                    <td><?php echo esc_html($rule['type']); ?></td>
                    <td><?php echo esc_html($rule['pattern']); ?></td>
                    <td><?php echo esc_html($rule['action']); ?></td>
                    <td><?php echo esc_html($rule['severity']); ?></td>
                    <td>
                        <form method="post" action="" style="display: inline;">
                            <?php wp_nonce_field('safeguard_remove_rule'); ?>
                            <input type="hidden" name="rule_id" value="<?php echo esc_attr($rule_id); ?>">
                            <button type="submit" name="remove_rule" class="button button-small button-link-delete">Remove</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    // Attack Comparison Chart
    var attackCtx = document.getElementById('attack-comparison-chart').getContext('2d');
    new Chart(attackCtx, {
        type: 'line',
        data: {
            labels: Array.from({length: 24}, (_, i) => i + ':00'),
            datasets: [{
                label: 'Today',
                data: <?php echo json_encode($hourly_data['today']); ?>,
                borderColor: 'rgb(54, 162, 235)',
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                fill: true
            }, {
                label: 'Yesterday',
                data: <?php echo json_encode($hourly_data['yesterday']); ?>,
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                fill: true
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Attacks by Hour'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });

    // Attack Types Chart
    var typesCtx = document.getElementById('attack-types-chart').getContext('2d');
    new Chart(typesCtx, {
        type: 'doughnut',
        data: {
            labels: <?php echo json_encode(array_map(function($a) { return $a->attack_type; }, $attack_types)); ?>,
            datasets: [{
                data: <?php echo json_encode(array_map(function($a) { return $a->count; }, $attack_types)); ?>,
                backgroundColor: [
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(54, 162, 235, 0.8)',
                    'rgba(255, 206, 86, 0.8)',
                    'rgba(75, 192, 192, 0.8)',
                    'rgba(153, 102, 255, 0.8)'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                },
                title: {
                    display: true,
                    text: 'Attack Types Distribution'
                }
            }
        }
    });
});
</script>
