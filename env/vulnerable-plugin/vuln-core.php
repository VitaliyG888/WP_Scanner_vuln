<?php
/**
 * Plugin Name: Vuln Lab Core
 * Description: Intentionally vulnerable WordPress test harness for the WP scanner. DO NOT DEPLOY TO PRODUCTION.
 * Version: 1.0.0
 * Author: WP Scanner Lab
 * License: MIT
 * Text Domain: vulnlab
 *
 * Every block below plants a well-known vulnerability class so that the
 * scanner can be validated against a known ground truth (see env/ground-truth.json).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * NOTE ON wp_unslash().
 * WordPress applies "magic quotes" to every request superglobal (wp_magic_quotes),
 * so a literal ' arrives as \' and " arrives as \". Real world plugins that end up
 * being injectable call wp_unslash()/stripslashes() on the input first - which is
 * exactly what this lab does, so that the planted bugs are actually exploitable.
 */

// ---------------------------------------------------------------------------
// [GROUND-TRUTH: hardcoded_secret] Hardcoded API key / DB password.
define( 'VULNLAB_API_KEY', 'sk-live-a1b2c3d4e5f6g7h8i9j0' );
$vulnlab_db_password = 'R00t-Password-123456';
// ---------------------------------------------------------------------------

/**
 * [GROUND-TRUTH: sqli] Unauthenticated SQL injection.
 * $wpdb->get_col() receives a string built by concatenating $_GET['u']
 * and is NOT wrapped in $wpdb->prepare().
 */
add_action( 'wp_ajax_nopriv_vulnlab_search', 'vulnlab_search' );
function vulnlab_search() {
	global $wpdb;
	$u    = wp_unslash( $_GET['u'] );
	$rows = $wpdb->get_col( "SELECT user_login FROM {$wpdb->users} WHERE user_login = '" . $u . "'" );
	echo 'VULNLAB-OK:' . count( $rows );
	exit;
}

/**
 * [GROUND-TRUTH: rce] Unauthenticated command injection.
 * system_exec() receives $_GET['cmd'] directly.
 */
add_action( 'wp_ajax_nopriv_vulnlab_exec', 'vulnlab_exec' );
function vulnlab_exec() {
	$cmd = wp_unslash( $_GET['cmd'] );
	echo 'VULNLAB-OK:';
	system( 'id; ' . $cmd );
	exit;
}

/**
 * [GROUND-TRUTH: lfi] Unauthenticated arbitrary file read / local file inclusion.
 */
add_action( 'wp_ajax_nopriv_vulnlab_read', 'vulnlab_read' );
function vulnlab_read() {
	$file = wp_unslash( $_GET['file'] );
	echo 'VULNLAB-OK:';
	readfile( $file );
	exit;
}

/**
 * [GROUND-TRUTH: file_upload] Unauthenticated arbitrary file upload.
 * Only a weak strpos() check is performed, so "shell.php.jpg" style names
 * (or a plain .php in this lab) are accepted and stored inside uploads/.
 */
add_action( 'wp_ajax_nopriv_vulnlab_upload', 'vulnlab_upload' );
function vulnlab_upload() {
	$name = $_FILES['shell']['name'];
	$tmp  = $_FILES['shell']['tmp_name'];
	if ( strpos( $name, '.php' ) === 0 ) {
		status_header( 403 );
		echo 'VULNLAB-REJECT';
		exit;
	}
	$dir  = ABSPATH . 'wp-content/uploads/vulnlab/';
	wp_mkdir_p( $dir );
	$dest = $dir . $name;
	if ( move_uploaded_file( $tmp, $dest ) ) {
		echo 'VULNLAB-UPLOADED:' . $name;
	} else {
		echo 'VULNLAB-FAIL';
	}
	exit;
}

/**
 * [GROUND-TRUTH: xss] Reflected XSS, output is not escaped with esc_html().
 */
add_action( 'wp_ajax_nopriv_vulnlab_xss', 'vulnlab_xss' );
function vulnlab_xss() {
	$msg = wp_unslash( $_GET['msg'] );
	echo '<span class="vulnlab-msg">' . $msg . '</span>';
	exit;
}

/**
 * [GROUND-TRUTH: open_redirect] Open redirect via the Location header.
 */
add_action( 'wp_ajax_nopriv_vulnlab_redirect', 'vulnlab_redirect' );
function vulnlab_redirect() {
	$url = wp_unslash( $_GET['url'] );
	header( 'Location: ' . $url );
	exit;
}

/**
 * [GROUND-TRUTH: deserialization] Insecure deserialization of user input.
 */
add_action( 'wp_ajax_nopriv_vulnlab_unpack', 'vulnlab_unpack' );
function vulnlab_unpack() {
	$data = wp_unslash( $_POST['data'] );
	$obj  = unserialize( $data );
	echo 'VULNLAB-OK:' . gettype( $obj );
	exit;
}

/**
 * [GROUND-TRUTH: weak_hash] Passwords hashed with MD5 (no wp_hash_password()).
 */
function vulnlab_hash_password( $password ) {
	return md5( $password );
}
