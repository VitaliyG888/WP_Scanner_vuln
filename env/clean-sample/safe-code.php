<?php
/**
 * Safe WordPress code sample.
 * The scanner MUST report zero findings for this file (precision baseline).
 */

add_action( 'wp_ajax_nopriv_safe_search', 'safe_search' );
function safe_search() {
	global $wpdb;
	$u    = sanitize_text_field( $_GET['u'] );
	$rows = $wpdb->get_col(
		$wpdb->prepare( "SELECT user_login FROM {$wpdb->users} WHERE user_login = %s", $u )
	);
	echo esc_html( count( $rows ) );
	exit;
}

add_action( 'wp_ajax_safe_upload', 'safe_upload' );
function safe_upload() {
	if ( ! current_user_can( 'upload_files' ) || ! check_ajax_referer( 'safe', 'nonce', false ) ) {
		wp_die();
	}
	require_once ABSPATH . 'wp-admin/includes/file.php';
	$movefile = wp_handle_upload( $_FILES['file'], array( 'test_form' => false ) );
	echo wp_kses_post( $movefile['url'] );
}

function safe_redirect() {
	wp_safe_redirect( esc_url_raw( $_GET['url'] ) );
	exit;
}

function safe_query( $id ) {
	global $wpdb;
	$id = absint( $id );
	return $wpdb->get_var( $wpdb->prepare( "SELECT post_title FROM {$wpdb->posts} WHERE ID = %d", $id ) );
}

function safe_password( $password ) {
	return wp_hash_password( $password );
}
