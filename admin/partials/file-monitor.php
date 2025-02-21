<?php
if (!defined('ABSPATH')) {
    exit;
}

global $wpdb;

// Get file changes
$recent_changes = $wpdb->get_results("
    SELECT * 
    FROM {$wpdb->prefix}safeguard_file_changes
    ORDER BY detected_at DESC 
    LIMIT 50
");

// Get monitored paths
$custom_paths = get_option('safeguard_monitored_paths', array());
$critical_files = json_decode(get_option('safeguard_critical_files', '[]'), true);

// Get monitoring settings
$monitoring_enabled = get_option('safeguard_file_monitoring', 1);
$scan_frequency = get_option('safeguard_scan_frequency', 'hourly');
$notify_changes = get_option('safeguard_notify_file_changes', 1);
$last_scan = get_option('safeguard_last_scan', 0);
?>

<div class="safeguard-tab-content" id="file-monitor">
    <div class="safeguard-row">
        <div class="safeguard-column">
            <div class="safeguard-card">
                <h3>File Monitoring Settings</h3>
                <form method="post" action="" class="safeguard-form">
                    <?php wp_nonce_field('safeguard_file_monitor_settings'); ?>
                    <div class="safeguard-form-group">
                        <label>
                            <input type="checkbox" name="monitoring_enabled" value="1" <?php checked($monitoring_enabled); ?>>
                            Enable File Monitoring
                        </label>
                    </div>
                    
                    <div class="safeguard-form-group">
                        <label for="scan_frequency">Scan Frequency</label>
                        <select name="scan_frequency" id="scan_frequency">
                            <option value="hourly" <?php selected($scan_frequency, 'hourly'); ?>>Hourly</option>
                            <option value="twicedaily" <?php selected($scan_frequency, 'twicedaily'); ?>>Twice Daily</option>
                            <option value="daily" <?php selected($scan_frequency, 'daily'); ?>>Daily</option>
                            <option value="weekly" <?php selected($scan_frequency, 'weekly'); ?>>Weekly</option>
                        </select>
                    </div>
                    
                    <div class="safeguard-form-group">
                        <label>
                            <input type="checkbox" name="notify_changes" value="1" <?php checked($notify_changes); ?>>
                            Email Notifications for File Changes
                        </label>
                    </div>
                    
                    <button type="submit" name="save_monitor_settings" class="button button-primary">Save Settings</button>
                </form>
            </div>

            <div class="safeguard-card">
                <h3>Add Custom Monitored Path</h3>
                <form method="post" action="" class="safeguard-form">
                    <?php wp_nonce_field('safeguard_add_monitored_path'); ?>
                    <div class="safeguard-form-group">
                        <label for="new_path">Path to Monitor</label>
                        <input type="text" name="new_path" id="new_path" required>
                    </div>
                    <button type="submit" name="add_monitored_path" class="button button-primary">Add Path</button>
                </form>
            </div>

            <div class="safeguard-card">
                <h3>Currently Monitored Paths</h3>
                <table class="safeguard-table">
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Type</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($critical_files as $file): ?>
                        <tr>
                            <td><?php echo esc_html($file); ?></td>
                            <td><span class="badge badge-primary">Critical</span></td>
                            <td>-</td>
                        </tr>
                        <?php endforeach; ?>
                        
                        <?php foreach ($custom_paths as $path): ?>
                        <tr>
                            <td><?php echo esc_html($path); ?></td>
                            <td><span class="badge badge-secondary">Custom</span></td>
                            <td>
                                <form method="post" action="" style="display: inline;">
                                    <?php wp_nonce_field('safeguard_remove_path'); ?>
                                    <input type="hidden" name="path_to_remove" value="<?php echo esc_attr($path); ?>">
                                    <button type="submit" name="remove_path" class="button button-small button-link-delete">Remove</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="safeguard-column">
            <div class="safeguard-card">
                <h3>Recent File Changes</h3>
                <?php if ($last_scan): ?>
                <p class="last-scan-info">Last scan completed: <?php echo esc_html(human_time_diff($last_scan)); ?> ago</p>
                <?php endif; ?>
                
                <div class="file-changes-chart-container">
                    <canvas id="file-changes-chart"></canvas>
                </div>
                
                <table class="safeguard-table">
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Change Type</th>
                            <th>Time</th>
                            <th>Details</th>
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
                            <td><?php echo esc_html(human_time_diff(strtotime($change->detected_at))); ?> ago</td>
                            <td>
                                <button class="button button-small show-details" 
                                        data-file="<?php echo esc_attr($change->file_path); ?>"
                                        data-details='<?php echo esc_attr(json_encode(array(
                                            'hash' => $change->file_hash,
                                            'size' => $change->file_size,
                                            'permissions' => $change->file_permissions,
                                            'detected_at' => $change->detected_at
                                        ))); ?>'>
                                    View Details
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- File Change Details Modal -->
<div id="file-details-modal" class="safeguard-modal">
    <div class="safeguard-modal-content">
        <span class="close">&times;</span>
        <h2>File Change Details</h2>
        <div id="file-details-content"></div>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    // Initialize the file changes chart
    var ctx = document.getElementById('file-changes-chart').getContext('2d');
    var data = {
        labels: <?php 
            $dates = array();
            $counts = array('modified' => array(), 'added' => array(), 'deleted' => array());
            for ($i = 6; $i >= 0; $i--) {
                $date = date('Y-m-d', strtotime("-$i days"));
                $dates[] = date('M d', strtotime($date));
                foreach ($counts as $type => &$count) {
                    $count[] = $wpdb->get_var($wpdb->prepare(
                        "SELECT COUNT(*) FROM {$wpdb->prefix}safeguard_file_changes 
                        WHERE DATE(detected_at) = %s AND change_type = %s",
                        $date, $type
                    )) ?: 0;
                }
            }
            echo json_encode($dates);
        ?>,
        datasets: [
            {
                label: 'Modified Files',
                data: <?php echo json_encode($counts['modified']); ?>,
                borderColor: 'rgb(54, 162, 235)',
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                fill: true
            },
            {
                label: 'Added Files',
                data: <?php echo json_encode($counts['added']); ?>,
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.1)',
                fill: true
            },
            {
                label: 'Deleted Files',
                data: <?php echo json_encode($counts['deleted']); ?>,
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                fill: true
            }
        ]
    };
    
    new Chart(ctx, {
        type: 'line',
        data: data,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'File Changes Over Time'
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

    // Modal functionality
    $('.show-details').click(function() {
        var details = $(this).data('details');
        var file = $(this).data('file');
        var content = `
            <table class="safeguard-table">
                <tr>
                    <th>File Path:</th>
                    <td>${file}</td>
                </tr>
                <tr>
                    <th>File Hash:</th>
                    <td>${details.hash || 'N/A'}</td>
                </tr>
                <tr>
                    <th>File Size:</th>
                    <td>${details.size ? formatBytes(details.size) : 'N/A'}</td>
                </tr>
                <tr>
                    <th>Permissions:</th>
                    <td>${details.permissions || 'N/A'}</td>
                </tr>
                <tr>
                    <th>Detected:</th>
                    <td>${new Date(details.detected_at).toLocaleString()}</td>
                </tr>
            </table>
        `;
        
        $('#file-details-content').html(content);
        $('#file-details-modal').show();
    });

    $('.close').click(function() {
        $('#file-details-modal').hide();
    });

    $(window).click(function(e) {
        if ($(e.target).is('#file-details-modal')) {
            $('#file-details-modal').hide();
        }
    });

    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
});
</script>
