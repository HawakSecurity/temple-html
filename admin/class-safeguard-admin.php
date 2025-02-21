<?php
class SafeGuard_Admin {
    public function init() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
    }

    public function add_admin_menu() {
        add_menu_page(
            'SafeGuardWP',
            'SafeGuardWP',
            'manage_options',
            'safeguardwp',
            array($this, 'display_dashboard'),
            'dashicons-shield',
            100
        );
    }

    public function enqueue_admin_assets($hook) {
        if ($hook !== 'toplevel_page_safeguardwp') {
            return;
        }

        wp_enqueue_style(
            'safeguard-admin',
            SAFEGUARD_PLUGIN_URL . 'admin/css/safeguard-admin.css',
            array(),
            SAFEGUARD_VERSION
        );

        wp_enqueue_script(
            'safeguard-admin',
            SAFEGUARD_PLUGIN_URL . 'admin/js/safeguard-admin.js',
            array('jquery'),
            SAFEGUARD_VERSION,
            true
        );
        wp_enqueue_script( 'chartjs', 'https://cdn.jsdelivr.net/npm/chart.js', array(), '3.9.1', true ); //added chart.js
        wp_localize_script('safeguard-admin', 'safeguardWP', array(
            'nonce' => wp_create_nonce('safeguard-nonce'),
            'ajaxurl' => admin_url('admin-ajax.php')
        ));
    }

    public function display_dashboard() {
        include SAFEGUARD_PLUGIN_DIR . 'admin/partials/dashboard-display.php';
    }
}