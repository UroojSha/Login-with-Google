<?php
/**
 * Plugin Name: CodeWoo Google Login
 * Plugin URI: https://code-woo-insider.free.nf/plugins/codewoo-google-login
 * Description: Adds a "Sign in with Google" button for user authentication.
 * Version: 1.0.0
 * Author: Urooj Shafait
 * Author URI: https://code-woo-insider.free.nf/
 * Text Domain: codewoo-google-login
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 5.5
 * Requires PHP: 7.4
 * 
 * @package CodeWooGoogleLogin
 */

defined('ABSPATH') || exit;

// Ensure the Composer autoload file is included.
require_once __DIR__ . '/vendor/autoload.php';

use League\OAuth2\Client\Provider\Google;

// Register plugin settings
add_action('admin_init', 'codewoo_google_login_register_settings');
function codewoo_google_login_register_settings() {
    register_setting('codewoo_google_login_settings_group', 'codewoo_google_login_client_id');
    register_setting('codewoo_google_login_settings_group', 'codewoo_google_login_client_secret');
    register_setting('codewoo_google_login_settings_group', 'codewoo_google_login_redirect_uri');
}

// Add settings page to admin menu
add_action('admin_menu', 'codewoo_google_login_add_settings_page');
function codewoo_google_login_add_settings_page() {
    add_menu_page(
        'Google Login Settings',
        'Google Login',
        'manage_options',
        'codewoo-google-login-settings',
        'codewoo_google_login_settings_page_callback',
        'dashicons-google',
        100 // Position in menu
    );
}

// Settings page callback function
function codewoo_google_login_settings_page_callback() {
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <form method="post" action="options.php">
            <?php settings_fields('codewoo_google_login_settings_group'); ?>
            <?php do_settings_sections('codewoo_google_login_settings_group'); ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Client ID</th>
                    <td><input type="text" name="codewoo_google_login_client_id" value="<?php echo esc_attr(get_option('codewoo_google_login_client_id')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Client Secret</th>
                    <td><input type="text" name="codewoo_google_login_client_secret" value="<?php echo esc_attr(get_option('codewoo_google_login_client_secret')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Redirect URI</th>
                    <td><input type="text" name="codewoo_google_login_redirect_uri" value="<?php echo esc_attr(get_option('codewoo_google_login_redirect_uri')); ?>" /></td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

// Retrieve Google OAuth URL with saved settings
function codewoo_google_login_get_auth_url() {
    $clientID = get_option('codewoo_google_login_client_id');
    $clientSecret = get_option('codewoo_google_login_client_secret');
    $redirectUri = get_option('codewoo_google_login_redirect_uri');

    $provider = new Google([
        'clientId'     => $clientID,
        'clientSecret' => $clientSecret,
        'redirectUri'  => $redirectUri,
    ]);

    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();

    return $authUrl;
}

// Update redirect URI in admin-ajax.php callback
add_action('admin_init', 'codewoo_google_login_update_redirect_uri');
function codewoo_google_login_update_redirect_uri() {
    $redirectUri = admin_url('admin-ajax.php?action=codewoo_google_login_callback');
    update_option('codewoo_google_login_redirect_uri', $redirectUri);
}

// Shortcode for Google login button
add_shortcode('codewoo_google_login_button', 'codewoo_google_login_button_shortcode');
function codewoo_google_login_button_shortcode() {
    if (is_user_logged_in()) {
        $current_user = wp_get_current_user();
        return '<p>Hi ' . esc_html($current_user->display_name) . '!</p><a href="' . esc_url(wp_logout_url(home_url())) . '"><button style="background-color: #DB4437; color: #FFFFFF; border: none; padding: 10px 20px; border-radius: 5px; font-size: 16px; cursor: pointer;">Logout</button></a>';
    }

    $googleAuthUrl = codewoo_google_login_get_auth_url();

    return '<a href="' . esc_url($googleAuthUrl) . '"><button style="background-color: #DB4437; color: #FFFFFF; border: none; padding: 10px 20px; border-radius: 5px; font-size: 16px; cursor: pointer;">Sign in with Google</button></a>';
}

// Handle Google OAuth callback
add_action('wp_ajax_nopriv_codewoo_google_login_callback', 'codewoo_google_login_callback');
function codewoo_google_login_callback() {
    $clientID = get_option('codewoo_google_login_client_id');
    $clientSecret = get_option('codewoo_google_login_client_secret');
    $redirectUri = get_option('codewoo_google_login_redirect_uri');

    $provider = new Google([
        'clientId'     => $clientID,
        'clientSecret' => $clientSecret,
        'redirectUri'  => $redirectUri,
    ]);

    if (isset($_GET['error'])) {
        wp_die('Got error: ' . htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8'));
    } elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
        wp_die('Invalid state.');
    } else {
        try {
            $token = $provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);

            $user = $provider->getResourceOwner($token);
            $userData = $user->toArray();

            $userEmail = $userData['email'];
            $userName = $userData['name'];

            $user = get_user_by('email', $userEmail);
            if (!$user) {
                $random_password = wp_generate_password(12, false);
                $user_id = wp_create_user($userName, $random_password, $userEmail);
                $user = get_user_by('id', $user_id);
            }

            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);
            wp_redirect(home_url());
            exit;
        } catch (Exception $e) {
            wp_die('Failed to get user details: ' . $e->getMessage());
        }
    }
}

// Enqueue jQuery script if user is not logged in
add_action('wp_enqueue_scripts', 'codewoo_google_login_scripts');
function codewoo_google_login_scripts() {
    if (!is_user_logged_in()) {
        wp_enqueue_script('jquery');
    }
}
