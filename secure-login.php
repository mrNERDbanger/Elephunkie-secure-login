<?php

/**
 * Plugin Name: Elephunkie Secure Login
 * Description: Automatically logs in specific users based on IP address whenever they visit any page, now with AJAX for instant login.
 * Version: 1.3.0
 * Author: Jonathan Albiar & ChatGPT
 * Author URI: https://elephunkie.com
 * Text Domain: elephunkie-secure-login
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('ELEPHUNKIE_SECURE_LOGIN_VERSION', '1.3.0');
define('ELEPHUNKIE_SECURE_LOGIN_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ELEPHUNKIE_SECURE_LOGIN_PLUGIN_URL', plugin_dir_url(__FILE__));

// Load WordPress core files
require_once(ABSPATH . 'wp-admin/includes/plugin.php');
require_once(ABSPATH . 'wp-includes/pluggable.php');
require_once(ABSPATH . 'wp-includes/functions.php');

/**
 * Handles the AJAX auto-login process.
 */
function secure_auto_login_ajax()
{
    check_ajax_referer('secure_auto_login_nonce', 'nonce');

    $visitor_ip = $_SERVER['REMOTE_ADDR'];
    $users = get_users([
        'meta_query' => [
            'relation' => 'OR',
            [
                'key'   => 'auto_login_ip_1',
                'value' => $visitor_ip,
                'compare' => '='
            ],
            [
                'key'   => 'auto_login_ip_2',
                'value' => $visitor_ip,
                'compare' => '='
            ],
            [
                'key'   => 'auto_login_ip_3',
                'value' => $visitor_ip,
                'compare' => '='
            ]
        ]
    ]);

    // If multiple users found for this IP, check for cookie preference
    if (count($users) > 1 && !is_user_logged_in()) {
        $preferred_user_id = isset($_COOKIE['secure_auto_login_preference']) ?
            intval($_COOKIE['secure_auto_login_preference']) : 0;

        if ($preferred_user_id) {
            // Find the preferred user in our results
            foreach ($users as $user) {
                if ($user->ID === $preferred_user_id) {
                    $users = [$user];
                    break;
                }
            }
        } else {
            wp_send_json_success([
                'verification_needed' => true,
                'users' => count($users)
            ]);
            return;
        }
    }

    // If a single user is found and they're not logged in, log them in
    if (!empty($users) && !is_user_logged_in()) {
        $user = $users[0];
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true, time() + (30 * DAY_IN_SECONDS));

        // Set preference cookie
        setcookie(
            'secure_auto_login_preference',
            $user->ID,
            time() + (90 * DAY_IN_SECONDS),
            COOKIEPATH,
            COOKIE_DOMAIN,
            is_ssl(),
            true
        );

        // Get admin bar HTML if user can see it
        $admin_bar_html = '';
        if (is_admin_bar_showing()) {
            ob_start();
            wp_admin_bar_render();
            $admin_bar_html = ob_get_clean();
        }

        wp_send_json_success([
            'message' => 'User logged in successfully',
            'admin_bar' => $admin_bar_html
        ]);
    }

    wp_send_json_error(['message' => 'User not logged in']);
}
add_action('wp_ajax_secure_auto_login', 'secure_auto_login_ajax');
add_action('wp_ajax_nopriv_secure_auto_login', 'secure_auto_login_ajax');

/**
 * Handle email verification request
 */
function secure_auto_login_verify()
{
    check_ajax_referer('secure_auto_login_nonce', 'nonce');

    $email = isset($_POST['email']) ? sanitize_email($_POST['email']) : '';
    if (!$email) {
        wp_send_json_error(['message' => __('Please enter a valid email address.', 'secure-auto-login')]);
        return;
    }

    $visitor_ip = $_SERVER['REMOTE_ADDR'];

    // Find user with this email and IP
    $user = get_user_by('email', $email);
    if (!$user) {
        wp_send_json_error(['message' => __('No matching user found for this email address.', 'secure-auto-login')]);
        return;
    }

    // Verify IP is registered for this user
    $ip_matches = false;
    for ($i = 1; $i <= 3; $i++) {
        if (get_user_meta($user->ID, 'auto_login_ip_' . $i, true) === $visitor_ip) {
            $ip_matches = true;
            break;
        }
    }

    if (!$ip_matches) {
        wp_send_json_error(['message' => __('This email is not authorized for auto-login from this IP address.', 'secure-auto-login')]);
        return;
    }

    // Generate and store verification code
    $code = wp_generate_password(12, false);
    set_transient('sal_verify_' . $user->ID, [
        'code' => $code,
        'ip' => $visitor_ip
    ], 15 * MINUTE_IN_SECONDS);

    // Send verification email
    $subject = sprintf(__('Verify Your Login at %s', 'secure-auto-login'), get_bloginfo('name'));
    $message = sprintf(
        __("Someone is trying to auto-login from your IP address (%s).\n\nIf this was you, click this link to verify:\n%s\n\nThis link will expire in 15 minutes.", 'secure-auto-login'),
        $visitor_ip,
        add_query_arg([
            'sal_verify' => $code,
            'user_id' => $user->ID
        ], home_url())
    );

    if (wp_mail($user->user_email, $subject, $message)) {
        wp_send_json_success([
            'message' => __('Verification email sent! Please check your inbox and click the verification link.', 'secure-auto-login')
        ]);
    } else {
        wp_send_json_error(['message' => __('Failed to send verification email. Please try again.', 'secure-auto-login')]);
    }
}
add_action('wp_ajax_nopriv_secure_auto_login_verify', 'secure_auto_login_verify');

/**
 * Enqueue AJAX script to trigger login.
 */
function secure_enqueue_ajax_login_script()
{
    if (!is_user_logged_in()) {
        wp_enqueue_script(
            'secure-auto-login',
            plugin_dir_url(__FILE__) . 'assets/js/secure-auto-login.js',
            ['jquery'],
            '1.0',
            true
        );

        wp_localize_script('secure-auto-login', 'secureAutoLogin', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('secure_auto_login_nonce'),
            'site_url' => home_url(),
            'wp_logo' => admin_url('images/wordpress-logo.svg')
        ]);
    }
}
add_action('wp_enqueue_scripts', 'secure_enqueue_ajax_login_script');

/**
 * Add fields to user profile to store auto-login IPs.
 */
function secure_auto_login_user_profile_fields($user)
{
    if (!current_user_can('edit_user', $user->ID)) {
        return;
    }
?>
    <h3><?php esc_html_e('Auto-Login IP Addresses', 'secure-auto-login'); ?></h3>
    <table class="form-table">
        <?php for ($i = 1; $i <= 3; $i++) : ?>
            <tr>
                <th>
                    <label for="auto_login_ip_<?php echo $i; ?>">
                        <?php printf(esc_html__('IP Address %d', 'secure-auto-login'), $i); ?>
                    </label>
                </th>
                <td>
                    <input type="text"
                        name="auto_login_ip_<?php echo $i; ?>"
                        id="auto_login_ip_<?php echo $i; ?>"
                        value="<?php echo esc_attr(get_user_meta($user->ID, 'auto_login_ip_' . $i, true)); ?>"
                        class="regular-text"
                        pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$">
                </td>
            </tr>
        <?php endfor; ?>
    </table>
<?php
}
add_action('show_user_profile', 'secure_auto_login_user_profile_fields');
add_action('edit_user_profile', 'secure_auto_login_user_profile_fields');

/**
 * Save the auto-login IP addresses when the user profile is updated.
 */
function secure_save_auto_login_user_profile_fields($user_id)
{
    if (!current_user_can('edit_user', $user_id)) {
        return false;
    }

    // Verify nonce would be here if this was a form submission

    for ($i = 1; $i <= 3; $i++) {
        $ip_field = 'auto_login_ip_' . $i;
        if (isset($_POST[$ip_field])) {
            $ip = sanitize_text_field($_POST[$ip_field]);
            // Validate IP format
            if (empty($ip) || filter_var($ip, FILTER_VALIDATE_IP)) {
                update_user_meta($user_id, $ip_field, $ip);
            }
        }
    }
}
add_action('personal_options_update', 'secure_save_auto_login_user_profile_fields');
add_action('edit_user_profile_update', 'secure_save_auto_login_user_profile_fields');

/**
 * Auto-login users based on stored IP addresses.
 */
function secure_auto_login_anywhere()
{
    // Don't proceed if already logged in
    if (is_user_logged_in()) {
        return;
    }

    // Don't auto-login on login page or admin
    if (
        strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false ||
        strpos($_SERVER['REQUEST_URI'], 'wp-admin') !== false
    ) {
        return;
    }

    // Get visitor IP
    $visitor_ip = $_SERVER['REMOTE_ADDR'];

    // Query users who have this IP stored
    $users = get_users([
        'meta_query' => [
            'relation' => 'OR',
            [
                'key'   => 'auto_login_ip_1',
                'value' => $visitor_ip,
                'compare' => '='
            ],
            [
                'key'   => 'auto_login_ip_2',
                'value' => $visitor_ip,
                'compare' => '='
            ],
            [
                'key'   => 'auto_login_ip_3',
                'value' => $visitor_ip,
                'compare' => '='
            ]
        ]
    ]);

    if (!empty($users)) {
        $user = $users[0];
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true, time() + (30 * DAY_IN_SECONDS));
    }
}
add_action('template_redirect', 'secure_auto_login_anywhere');

/**
 * Add immediate auto-login attempt before page load
 */
function secure_auto_login_immediate()
{
    if (is_user_logged_in()) {
        return;
    }

    // Don't auto-login on login page or admin
    if (
        strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false ||
        strpos($_SERVER['REQUEST_URI'], 'wp-admin') !== false
    ) {
        return;
    }

    // Get visitor IP
    $visitor_ip = $_SERVER['REMOTE_ADDR'];

    // Query users who have this IP stored
    $users = get_users([
        'meta_query' => [
            'relation' => 'OR',
            [
                'key'   => 'auto_login_ip_1',
                'value' => $visitor_ip,
                'compare' => '='
            ],
            [
                'key'   => 'auto_login_ip_2',
                'value' => $visitor_ip,
                'compare' => '='
            ],
            [
                'key'   => 'auto_login_ip_3',
                'value' => $visitor_ip,
                'compare' => '='
            ]
        ]
    ]);

    if (!empty($users)) {
        $user = $users[0];
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true, time() + (30 * DAY_IN_SECONDS));

        // Redirect to same page to show logged-in state
        if (!defined('DOING_AJAX')) {
            wp_redirect($_SERVER['REQUEST_URI']);
            exit;
        }
    }
}
// Run this as early as possible
add_action('init', 'secure_auto_login_immediate', 1);

/**
 * Handle user selection for shared IPs
 */
function secure_auto_login_select_user()
{
    check_ajax_referer('secure_auto_login_nonce', 'nonce');

    $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;
    if (!$user_id) {
        wp_send_json_error(['message' => 'Invalid user selection']);
        return;
    }

    $visitor_ip = $_SERVER['REMOTE_ADDR'];

    // Verify this user has this IP registered
    $user_meta = get_user_meta($user_id);
    $ip_matches = false;
    for ($i = 1; $i <= 3; $i++) {
        if (
            isset($user_meta['auto_login_ip_' . $i][0]) &&
            $user_meta['auto_login_ip_' . $i][0] === $visitor_ip
        ) {
            $ip_matches = true;
            break;
        }
    }

    if (!$ip_matches) {
        wp_send_json_error(['message' => 'Unauthorized login attempt']);
        return;
    }

    // Log the user in
    $user = get_user_by('ID', $user_id);
    if ($user) {
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true, time() + (30 * DAY_IN_SECONDS));

        // Set preference cookie
        setcookie(
            'secure_auto_login_preference',
            $user->ID,
            time() + (90 * DAY_IN_SECONDS),
            COOKIEPATH,
            COOKIE_DOMAIN,
            is_ssl(),
            true
        );

        // Get admin bar HTML
        $admin_bar_html = '';
        if (is_admin_bar_showing()) {
            ob_start();
            wp_admin_bar_render();
            $admin_bar_html = ob_get_clean();
        }

        wp_send_json_success([
            'message' => 'User logged in successfully',
            'admin_bar' => $admin_bar_html
        ]);
    }

    wp_send_json_error(['message' => 'Login failed']);
}
add_action('wp_ajax_nopriv_secure_auto_login_select_user', 'secure_auto_login_select_user');

/**
 * Handle email verification links
 */
function secure_handle_verification()
{
    if (isset($_GET['sal_verify']) && isset($_GET['user_id'])) {
        $user_id = intval($_GET['user_id']);
        $code = sanitize_text_field($_GET['sal_verify']);

        $verify_data = get_transient('sal_verify_' . $user_id);

        if ($verify_data && $verify_data['code'] === $code) {
            // Set the preference cookie
            setcookie(
                'secure_auto_login_preference',
                $user_id,
                time() + (90 * DAY_IN_SECONDS),
                COOKIEPATH,
                COOKIE_DOMAIN,
                is_ssl(),
                true
            );

            // Log the user in
            $user = get_user_by('ID', $user_id);
            if ($user) {
                wp_set_current_user($user->ID);
                wp_set_auth_cookie($user->ID, true, time() + (30 * DAY_IN_SECONDS));

                // Clean up
                delete_transient('sal_verify_' . $user_id);

                // Redirect to home
                wp_safe_redirect(home_url());
                exit;
            }
        }
    }
}
add_action('init', 'secure_handle_verification');
