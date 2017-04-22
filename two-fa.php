<?php
/**
 * Plugin Name: Two Fa
 * Plugin URI: trepmal.com
 * Description: 2FA on a budget. (lazy/demo)
 * Version: 0.0.1
 * Author: Kailey Lampert
 * Author URI: kaileylampert.com
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * TextDomain: 2fa
 * DomainPath:
 * Network:
 *
 * @package trepmal/Two_Fa
 */

$twofa = new Two_Fa();

/**
 * 2fa
 */
class Two_Fa {

	/**
	 * Get hooked in
	 */
	function __construct() {
		add_action( 'authenticate', array( $this, 'authenticate' ), 10, 3 );
		add_action( 'login_form_login', array( $this, 'do_2fa' ) );
	}

	/**
	 * Authenticate
	 *
	 * @param null|WP_User|WP_Error $user     WP_User if the user is authenticated.
	 *                                        WP_Error or null otherwise.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return WP_User|false User or Error
	 */
	function authenticate( $user, $username, $password ) {

		// Validiate 2fa code
		if ( isset( $_POST['2fa-code'] ) ) {

			// No cookie.
			if ( ! isset( $_COOKIE['2fa'] ) ) {
				$error = new WP_Error();
				$error->add( 'no_cookies', __( 'You must enable cookies.', 'two-fa' ) );
				return $error;
			}

			$cook = rawurldecode( sanitize_text_field( wp_unslash( $_COOKIE['2fa'] ) ) );
			list( $uid, $code ) = explode( '|', $cook );

			$twofa_code = sanitize_text_field( wp_unslash( $_POST['2fa-code'] ) );

			// No 2fa match.
			if ( 'magic code' !== $twofa_code ) {

				$redirect = add_query_arg( array(
					'action' => 'intercept',
					'fail'   => '',
				), wp_login_url() );

				wp_redirect( $redirect );
				exit;
			}

			// Got what we need, dispose.
			setcookie( '2fa', '', time() - 3000 );

			$saved_code  = get_user_meta( $uid, 'signin_code', true );
			$saved_valid = get_user_meta( $uid, 'signin_valid', true );

			$user = get_user_by( 'id', $uid );

			// User not found.
			if ( false === $user ) {
				$error = new WP_Error();
				$error->add( 'invalid_attempt', __( 'Invalid attempt.', 'two-fa' ) );
				return $error;
			}

			// No pre-auth.
			if ( empty( $saved_code ) || empty( $saved_valid ) ) {
				$error = new WP_Error();
				$error->add( 'invalid_attempt', __( 'Invalid attempt.', 'two-fa' ) );
				return $error;
			}

			// Expired pre-auth.
			if ( $saved_valid < time() ) {
				$error = new WP_Error();
				$error->add( 'code_expired', __( 'Code expired.', 'two-fa' ) );
				return $error;
			}

			// No pre-auth match.
			if ( $saved_code != $code ) {
				$error = new WP_Error();
				$error->add( 'code_mismatch', __( 'Code mismatch.', 'two-fa' ) );
				return $error;
			}

			// Passes all checks, log in.
			return get_user_by( 'id', $uid );
		}

		if ( is_null( $user ) && empty( $username ) && empty( $password ) ) {
			return $user;
		}

		remove_all_filters( 'authenticate' );
		$user = wp_authenticate_username_password( null, $username, $password );

		if ( is_a( $user, 'WP_User' ) ) {

			// Generate code and expiration.
			$rand = function_exists( 'random_int' ) ? random_int( 111, 999999999 ) : mt_rand();
			$code = md5( time() . $rand . site_url() . $_SERVER['REMOTE_ADDR'] );
			$valid = strtotime( '+10 minutes' );

			// Save code/expiration.
			setcookie('2fa', "{$user->ID}|$code", $valid );
			update_user_meta( $user->ID, 'signin_code', $code );
			update_user_meta( $user->ID, 'signin_valid', $valid );

			$redirect = add_query_arg( array(
				'action' => 'intercept',
			), wp_login_url() );

			wp_redirect( $redirect );
			exit;

		} else {
			return $user;
		}
	}

	/**
	 * Do screen
	 */
	function do_2fa() {
		if ( ! isset( $_GET['action'] ) || 'intercept' !== $_GET['action'] ) {
			return;
		}

		if ( ! isset( $_COOKIE['2fa'] ) ) {
			return;
		}

		$error = new WP_Error();
		if ( isset( $_GET['fail'] ) ) {
			$error->add( '2fa_failed', __( 'Verification failed. Try again.', 'two-fa' ) );
		}

		login_header( __( 'Verify', 'two-fa' ), '', $error );

		?>
		<form method="post" action="wp-login.php">
		<p><label><?php esc_html_e( 'Verification code', 'two-fa' ); ?><br />
		<input type="text" name="2fa-code" /></label></p>
		<p><input type="submit" class="button button-primary" /></p>
		</form>
		<?php

		login_footer();
		die;

	}
}
