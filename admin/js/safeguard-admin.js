(function($) {
    'use strict';

    $(document).ready(function() {
        // Initialize security score circle
        const score = parseInt($('.score-number').text());
        $('.score-circle').css('--score', score + '%');

        // Tab switching with animations
        $('.safeguard-tab-link').on('click', function(e) {
            e.preventDefault();
            var target = $(this).data('tab');

            $('.safeguard-tab-link').removeClass('active');
            $(this).addClass('active');

            $('.safeguard-tab-content').fadeOut(300).promise().done(function() {
                $('#' + target).fadeIn(300);
            });
        });

        // Form submission handler - for all settings forms
        $('#notification-settings-form, #firewall-settings-form, #file-monitor-settings-form, #general-settings-form').on('submit', function(e) {
            e.preventDefault();
            var $form = $(this);
            var $submitButton = $form.find('button[type="submit"]');
            var $message = $form.find('.safeguard-form-message');

            $submitButton.prop('disabled', true).text('Saving...');
            $message.removeClass('success error').empty();

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'save_safeguard_settings',
                    form_id: 'notification-settings-form',
                    formData: $form.serialize(),
                    nonce: $('#safeguard_notification_nonce').val()
                },
                success: function(response) {
                    if (response.success) {
                        showNotification('Settings saved successfully!', 'success');
                        $message.addClass('success').text('Settings saved successfully!');
                    } else {
                        showNotification('Error saving settings: ' + (response.data || 'Unknown error'), 'error');
                        $message.addClass('error').text('Error saving settings: ' + (response.data || 'Unknown error'));
                    }
                },
                error: function(xhr, status, error) {
                    var errorMessage = 'Error saving settings: ' + error;
                    showNotification(errorMessage, 'error');
                    $message.addClass('error').text(errorMessage);
                },
                complete: function() {
                    $submitButton.prop('disabled', false).text('Save Notification Settings');
                }
            });
        });

        // Save settings with AJAX - for other forms
        $('#safeguard-settings-form, #firewall-settings-form, #file-monitor-settings-form').on('submit', function(e) {
            e.preventDefault();
            var $form = $(this);
            var formData = $form.serialize();
            var $submitButton = $form.find('button[type="submit"]');
            var formId = $form.attr('id');
            var $message = $form.find('.safeguard-form-message');

            $submitButton.prop('disabled', true).text('Saving...');
            $message.removeClass('success error').empty();

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'save_safeguard_settings',
                    form_id: formId,
                    formData: formData,
                    nonce: safeguardWP.nonce
                },
                success: function(response) {
                    if (response.success) {
                        showNotification('Settings saved successfully!', 'success');
                        $message.addClass('success').text('Settings saved successfully!');
                    } else {
                        showNotification('Error saving settings.', 'error');
                        $message.addClass('error').text('Error saving settings.');
                    }
                },
                error: function(xhr, status, error) {
                    var errorMessage = 'Error saving settings: ' + error;
                    showNotification(errorMessage, 'error');
                    $message.addClass('error').text(errorMessage);
                },
                complete: function() {
                    $submitButton.prop('disabled', false).text('Save Settings');
                }
            });
        });

        // Notification display function
        function showNotification(message, type) {
            var $notification = $('<div>', {
                class: 'safeguard-alert safeguard-alert-' + type,
                text: message
            }).appendTo('.safeguard-wrap');

            setTimeout(function() {
                $notification.fadeOut(300, function() {
                    $(this).remove();
                });
            }, 3000);
        }

        // Real-time updates for security events
        function updateSecurityStats() {
            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'get_security_stats',
                    nonce: safeguardWP.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $('.stat-blocked .safeguard-stat-number').text(response.data.blocked);
                        $('.stat-critical .safeguard-stat-number').text(response.data.critical);
                        $('.stat-banned .safeguard-stat-number').text(response.data.banned);
                        $('.stat-files .safeguard-stat-number').text(response.data.files);
                    }
                }
            });
        }

        // Update stats every 30 seconds
        setInterval(updateSecurityStats, 30000);

        // Initialize attack trends chart
        var attackTrendsChart = document.getElementById('attack-trends-chart');
        if (attackTrendsChart) {
            var ctx = attackTrendsChart.getContext('2d');
            var gradientFill = ctx.createLinearGradient(0, 0, 0, 400);
            gradientFill.addColorStop(0, 'rgba(54, 162, 235, 0.2)');
            gradientFill.addColorStop(1, 'rgba(54, 162, 235, 0)');

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: window.chartLabels || [],
                    datasets: [{
                        label: 'Total Attacks',
                        data: window.totalAttacks || [],
                        borderColor: 'rgb(54, 162, 235)',
                        backgroundColor: gradientFill,
                        tension: 0.4,
                        fill: true
                    }, {
                        label: 'Critical Attacks',
                        data: window.criticalAttacks || [],
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        intersect: false,
                        mode: 'index'
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                drawBorder: false
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top'
                        },
                        tooltip: {
                            backgroundColor: 'rgba(255, 255, 255, 0.9)',
                            titleColor: '#333',
                            bodyColor: '#666',
                            borderColor: '#e5e5e5',
                            borderWidth: 1,
                            padding: 10,
                            displayColors: true,
                            callbacks: {
                                label: function(context) {
                                    return context.dataset.label + ': ' + context.parsed.y;
                                }
                            }
                        }
                    }
                }
            });
        }

        // Attack Details Modal
        $(document).on('click', '.view-details, .details', function() {
            var attackId = $(this).data('attack-id');
            var modal = $('#attack-details-modal');

            // Show loading state
            $('#attack-details-content').html('<div class="loading">Loading attack details...</div>');
            modal.fadeIn();

            // Load details via AJAX
            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'get_attack_details',
                    attack_id: attackId,
                    nonce: safeguardWP.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var details = response.data;
                        var content = `
                            <div class="attack-details">
                                <h4>Attack Details</h4>
                                <div class="details-section">
                                    <h5>Basic Information</h5>
                                    <p><strong>Attack ID:</strong> ${details.id}</p>
                                    <p><strong>IP Address:</strong> ${details.ip_address}</p>
                                    <p><strong>Timestamp:</strong> ${details.timestamp}</p>
                                    <p><strong>Severity Score:</strong> ${details.severity_score}</p>
                                    <p><strong>Attack Type:</strong> ${details.attack_type}</p>
                                </div>

                                <div class="details-section">
                                    <h5>Request Details</h5>
                                    <p><strong>Method:</strong> ${details.request_method}</p>
                                    <p><strong>URI:</strong> ${details.request_uri}</p>
                                    <p><strong>User Agent:</strong> ${details.user_agent}</p>
                                </div>

                                <div class="details-section">
                                    <h5>Request Headers</h5>
                                    <pre>${details.headers}</pre>
                                </div>

                                <div class="details-section">
                                    <h5>Request Payload</h5>
                                    <pre>${details.payload}</pre>
                                </div>

                                <div class="details-section">
                                    <h5>Detection Details</h5>
                                    <pre>${details.detection_details}</pre>
                                </div>
                            </div>
                        `;
                        $('#attack-details-content').html(content);
                    } else {
                        $('#attack-details-content').html('<div class="error">Error loading attack details</div>');
                    }
                },
                error: function() {
                    $('#attack-details-content').html('<div class="error">Error loading attack details</div>');
                }
            });
        });

        // Close modal
        $('.close').on('click', function() {
            $('#attack-details-modal').fadeOut();
        });

        // Close modal when clicking outside
        $(window).on('click', function(event) {
            var modal = $('#attack-details-modal');
            if (event.target == modal[0]) {
                modal.fadeOut();
            }
        });

        // Block IP functionality
        $(document).on('click', '.block-ip', function() {
            var ip = $(this).data('ip');
            if (confirm('Are you sure you want to block IP ' + ip + '?')) {
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'block_ip',
                        ip: ip,
                        nonce: safeguardWP.nonce
                    },
                    success: function(response) {
                        if (response.success) {
                            showNotification('IP ' + ip + ' has been blocked', 'success');
                            location.reload();
                        } else {
                            showNotification('Failed to block IP', 'error');
                        }
                    }
                });
            }
        });
    });
})(jQuery);