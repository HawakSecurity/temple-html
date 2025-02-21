<?php
class SafeGuard_2FA {
    public function __construct() {
        if (get_option('safeguard_2fa_enabled', 0)) {
            add_action('wp_login', array($this, 'init_2fa'), 10, 2);
            add_action('wp_ajax_verify_2fa_code', array($this, 'verify_2fa_code'));
            add_action('wp_ajax_nopriv_verify_2fa_code', array($this, 'verify_2fa_code'));
        }
    }

    public function init_2fa($user_login, $user) {
        $code = $this->generate_2fa_code();
        update_user_meta($user->ID, 'safeguard_2fa_code', $code);
        update_user_meta($user->ID, 'safeguard_2fa_timestamp', time());

        // Send code via email
        $this->send_2fa_code($user->user_email, $code);

        // Show 2FA form
        wp_clear_auth_cookie();
        $this->show_2fa_form($user->ID);
        exit;
    }

    private function generate_2fa_code() {
        return sprintf('%06d', mt_rand(0, 999999));
    }

    private function send_2fa_code($email, $code) {
        $subject = 'Your Two-Factor Authentication Code';
        $message = sprintf(
            'Your two-factor authentication code is: %s%sThis code will expire in 5 minutes.',
            $code,
            "\n\n"
        );

        wp_mail($email, $subject, $message);
    }

    private function show_2fa_form($user_id) {
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Two-Factor Authentication</title>
            <style>
                body {
                    background: #f5f5f5;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                }
                .safeguard-2fa-container {
                    width: 320px;
                    margin: 100px auto;
                    padding: 30px;
                    background: #fff;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    text-align: center;
                }
                .safeguard-2fa-input {
                    width: 100%;
                    padding: 12px;
                    margin: 15px 0;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    font-size: 16px;
                    box-sizing: border-box;
                }
                .safeguard-2fa-button {
                    width: 100%;
                    padding: 12px;
                    background: #0085ba;
                    color: #fff;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                    transition: background 0.3s ease;
                }
                .safeguard-2fa-button:hover {
                    background: #006799;
                }
                .error-message {
                    color: #dc3232;
                    margin: 10px 0;
                    display: none;
                }
            </style>
        </head>
        <body>
            <div class="safeguard-2fa-container">
                <h2>Two-Factor Authentication</h2>
                <p>Please enter the verification code sent to your email.</p>
                <input type="text" id="2fa-code" class="safeguard-2fa-input" placeholder="Enter verification code">
                <input type="hidden" id="user-id" value="<?php echo esc_attr($user_id); ?>">
                <div id="error-message" class="error-message"></div>
                <button onclick="verify2FA()" class="safeguard-2fa-button">Verify</button>
            </div>

            <script>
            function verify2FA() {
                var code = document.getElementById('2fa-code').value;
                var userId = document.getElementById('user-id').value;
                var errorDiv = document.getElementById('error-message');
                var button = document.querySelector('.safeguard-2fa-button');

                // Disable button during verification
                button.disabled = true;
                button.textContent = 'Verifying...';
                errorDiv.style.display = 'none';

                var xhr = new XMLHttpRequest();
                xhr.open('POST', '<?php echo admin_url('admin-ajax.php'); ?>', true);
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

                xhr.onload = function() {
                    try {
                        var response = JSON.parse(xhr.responseText);
                        if (response.success) {
                            window.location.href = '<?php echo admin_url(); ?>';
                        } else {
                            errorDiv.textContent = response.message || 'Verification failed. Please try again.';
                            errorDiv.style.display = 'block';
                            button.disabled = false;
                            button.textContent = 'Verify';
                        }
                    } catch (e) {
                        errorDiv.textContent = 'An error occurred. Please try again.';
                        errorDiv.style.display = 'block';
                        button.disabled = false;
                        button.textContent = 'Verify';
                    }
                };

                xhr.onerror = function() {
                    errorDiv.textContent = 'Network error occurred. Please try again.';
                    errorDiv.style.display = 'block';
                    button.disabled = false;
                    button.textContent = 'Verify';
                };

                xhr.send('action=verify_2fa_code&code=' + encodeURIComponent(code) + '&user_id=' + encodeURIComponent(userId) + '&_wpnonce=' + '<?php echo wp_create_nonce('verify_2fa_code'); ?>');
            }
            </script>
        </body>
        </html>
        <?php
    }

    public function verify_2fa_code() {
        check_ajax_referer('verify_2fa_code');

        $code = isset($_POST['code']) ? sanitize_text_field($_POST['code']) : '';
        $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;

        if (empty($code) || empty($user_id)) {
            wp_send_json(array(
                'success' => false,
                'message' => 'Invalid request parameters.'
            ));
        }

        $stored_code = get_user_meta($user_id, 'safeguard_2fa_code', true);
        $timestamp = get_user_meta($user_id, 'safeguard_2fa_timestamp', true);

        if (time() - $timestamp > 300) { // 5 minutes expiration
            wp_send_json(array(
                'success' => false,
                'message' => 'Code has expired. Please try logging in again.'
            ));
        }

        if ($code === $stored_code) {
            delete_user_meta($user_id, 'safeguard_2fa_code');
            delete_user_meta($user_id, 'safeguard_2fa_timestamp');

            $user = get_user_by('ID', $user_id);
            wp_set_auth_cookie($user_id);
            wp_send_json(array(
                'success' => true,
                'message' => 'Verification successful.'
            ));
        } else {
            wp_send_json(array(
                'success' => false,
                'message' => 'Invalid verification code.'
            ));
        }
    }
}