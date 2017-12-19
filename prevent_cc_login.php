<?php
/**
 * The plugin bootstrap file
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              #
 * @since             1.0.0
 * @package           Prevent_cc_login
 *
 * @wordpress-plugin
 * Plugin Name:       Concurrent Login Prompt
 * Plugin URI:        #
 * Description:       This plugin prompt user to force login or not, if this is his/her concurrent login attempt.
 * Version:           1.0.0
 * Author:            Muhammad Humayun
 * Author URI:        #
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       prevent_cc_login
 * Domain Path:       /languages
 */
// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

define('ERROR_EXPIRED_NONCE', 100);

/*
 * Register callback methods for WordPress hooks
 */
add_filter('authenticate', 'alert_user_for_duplicate_attempt', 20, 3);
add_action('login_form_login_prompt', 'prompt_for_confirmation');
add_filter('wp_login_errors', 'show_login_error_message');

/*
 * All functions below
 */

/* Check multiple device login and redirect */

function alert_user_for_duplicate_attempt($user, $username, $attempted_password) {

    if (is_a($user, 'WP_User')) {

        /* This is for wordpress default login popup */
        $interim_login = isset($_REQUEST['interim-login']) ? $_REQUEST['interim-login'] : '';

        $wp_auth_up = wp_authenticate_username_password($user, $username, $attempted_password);

        if ($wp_auth_up) {    // they entered a valid username/email/password
            $sessions = WP_Session_Tokens::get_instance($user->ID);

            if (count($sessions->get_all()) >= 1) {
                /* Generate login nonce */
                $login_nonce = generate_login_nonce($user->ID);

                if ($interim_login) {
                    $redirect_url = sprintf(
                            '%s?action=login_prompt&user_id=%d&prevent_cc_login_nonce=%s%s%s', wp_login_url(), $user->ID, $login_nonce['nonce'], isset($interim_login) ? '&interim-login=' . $interim_login : '', isset($_REQUEST['rememberme']) ? '&remember_me=' . sanitize_text_field($_REQUEST['rememberme']) : ''
                    );
                } else {
                    $redirect_url = sprintf(
                            '%s?action=login_prompt&user_id=%d&prevent_cc_login_nonce=%s%s%s', wp_login_url(), $user->ID, $login_nonce['nonce'], isset($_REQUEST['redirect_to']) ? '&redirect_to=' . urlencode($_REQUEST['redirect_to']) : '', isset($_REQUEST['rememberme']) ? '&remember_me=' . sanitize_text_field($_REQUEST['rememberme']) : ''
                    );
                }

                wp_safe_redirect($redirect_url);
                die();
            }
        }
    }
    return $user;
}

/* Confirmation form */

function prompt_for_confirmation() {

    $interim_login = isset($_REQUEST['interim-login']) ? $_REQUEST['interim-login'] : '';
    $redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : '';
    $remember_me = isset($_REQUEST['remember_me']) ? sanitize_text_field($_REQUEST['remember_me']) : '';
    $action_url = add_query_arg(array('action' => 'login_prompt'), wp_login_url($redirect_to));
    $action_url = add_query_arg(array('remember_me' => $remember_me), $action_url);

    if (!isset($_REQUEST['user_id']) || !isset($_REQUEST['prevent_cc_login_nonce'])) {
        return;
    }

    $user = get_user_by('id', absint($_REQUEST['user_id']));

    if (!$user) {
        return;
    }

    $error_message = action_for_confirmation($_POST, $user);

    require_once plugin_dir_path(__FILE__) . 'includes/prevent_cc_login-prompt.php';
    exit();
}

/* Actions after confirmation */

function action_for_confirmation($form_posts, $user) {
    $error_message = '';
    $interim_login = isset($form_posts['interim-login']) ? $form_posts['interim-login'] : '';

    if (isset($form_posts['force_login_prompt']) && $form_posts['force_login_prompt'] == 'Yes') {
        if (is_a($user, 'WP_User')) {
            /* Destroy Other sessions of this user than this one */
            $sessions = WP_Session_Tokens::get_instance($user->ID);
            $sessions->destroy_all();
            $error_message = log_user_in($user, $interim_login);
        } elseif (is_wp_error($user)) {
            /** @var $user WP_Error */
            $error_message = $user->get_error_message();
        } else {
            $error_message = '<strong>ERROR:</strong> Token could not be validated';
        }
    }

    return $error_message;
}

/* Generate Login nonce */

function generate_login_nonce($user_id) {
    $login_nonce = array(
        'nonce' => wp_hash($user_id . wp_rand() . microtime(), 'nonce'),
        'expiration' => time() + apply_filters('prevent_cc_login_nonce_expiration', MINUTE_IN_SECONDS)
    );

    update_user_meta($user_id, 'prevent_cc_login_nonce', $login_nonce);

    return $login_nonce;
}

/* Login user in, after confirmation */

function log_user_in($user, $interim_login) {
    $credentials = array('user_login' => $user->user_login);

    if (!empty($_REQUEST['remember_me'])) {
        $credentials['remember'] = sanitize_text_field($_REQUEST['remember_me']);
    }

    remove_action('wp_login', 'alert_user_for_duplicate_attempt', 10);     // otherwise the user would be logged out and redirected back to the token form
    add_action('authenticate', 'original_login_verify', 40, 3);   // after username/password and cookie checks

    $user = wp_signon($credentials);

    remove_action('authenticate', 'original_login_verify', 40);

    if (is_a($user, 'WP_User')) {
        $redirect_url = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
        $requested_redirect_url = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : '';
        $redirect_url = apply_filters('prevent_cc_login_redirect_to', $redirect_url, $requested_redirect_url, $user);

        if ($interim_login) {
            $message = '<p class="message">' . __('You have logged in successfully.') . '</p>';
            $interim_login = 'success';
            login_header('', $message);
            ?>
            </div>
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.8.3/jquery.min.js"></script>
            <script type="text/javascript">
                setTimeout(function () {
                    wrap = $('#wp-auth-check-wrap', parent.document);
                    wrap.fadeOut(200, function () {
                        wrap.addClass('hidden').css('display', '');
                        $('#wp-auth-check-frame', parent.document).remove();
                        $('body', parent.document).removeClass('modal-open');
                    });
                }, 1000);
            </script>
            </body></html>
            <?php
            exit;
        }

        wp_safe_redirect($redirect_url);
        die();
    } elseif (is_wp_error($user)) { // will only get here if another plugin has an 'authenticate' filter running after ours
        return $user->get_error_message();
    } else {
        return '<strong>ERROR:</strong> Login attempt failed.';
    }
}

/* Verify original login */

function original_login_verify($user, $username, $password) {
    /*
     * Unlike in most `authenticate` callbacks, here $username is guaranteed to be the username (and not the
     * e-mail address) because the credentials are setup in $this->login_user().
     *
     * Therefore, unlike other callbacks, we don't need to check attempt getting the user by name and email.
     */
    $user = get_user_by('login', $username);

    if (login_nonce_verify($user->ID, $_POST['prevent_cc_login_nonce'])) {
        return $user;
    } else {
        $redirect_url = sprintf(
                '%s?prevent_cc_error=%s%s', wp_login_url(), ERROR_EXPIRED_NONCE, isset($_REQUEST['redirect_to']) ? '&redirect_to=' . urlencode($_REQUEST['redirect_to']) : ''
        );

        wp_safe_redirect($redirect_url);
        die();
    }
}

/* Verify submitted nonce */

function login_nonce_verify($user_id, $attempted_nonce) {
    $login_nonce = get_user_meta($user_id, 'prevent_cc_login_nonce', true);
    $valid = false;

    if (isset($login_nonce['nonce']) && hash_equals($attempted_nonce, $login_nonce['nonce'])) {
        if (time() < $login_nonce['expiration']) {
            delete_user_meta($user_id, 'prevent_cc_login_nonce');    // so it can only be used once
            $valid = true;
        }
    }

    return $valid;
}

/* Error (nonce missmatch error) handler */

function show_login_error_message($errors) {
    $code = isset($_REQUEST['prevent_cc_error']) ? $_REQUEST['prevent_cc_error'] : null;

    switch ($code) {
        case ERROR_EXPIRED_NONCE:
            $errors->add('prevent_cc_error' . ERROR_EXPIRED_NONCE, '<strong>ERROR:</strong> Your login nonce has expired. Please log in again.');
            break;
    }

    return $errors;
}

/* Helpers */

function get_user_sessions($user_id) {
    $sessions = get_user_meta($user_id, 'session_tokens', true);
    if (!is_array($sessions)) {
        return array();
    }
    return $sessions;
}

function debug($var) {
    echo "<pre>";
    print_r($var);
    echo "</pre>";
    die();
}
