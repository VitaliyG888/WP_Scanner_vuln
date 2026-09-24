<?php
/**
 * Non-interactive WordPress installer for the lab container.
 *
 * Runs inside the wordpress image (PHP + wp-load) so that no extra image such
 * as wordpress:cli has to be downloaded. Exits non-zero while the database is
 * still unavailable, which lets the compose wrapper retry.
 *
 * Environment overrides: WP_ROOT, WP_LAB_URL, WP_LAB_TITLE, WP_LAB_ADMIN_USER,
 * WP_LAB_ADMIN_PASSWORD, WP_LAB_ADMIN_EMAIL.
 */

$root  = getenv( 'WP_ROOT' ) ?: '/var/www/html';
$url   = getenv( 'WP_LAB_URL' ) ?: 'http://localhost:8080';
$title = getenv( 'WP_LAB_TITLE' ) ?: 'Vuln Lab';
$user  = getenv( 'WP_LAB_ADMIN_USER' ) ?: 'admin';
$pass  = getenv( 'WP_LAB_ADMIN_PASSWORD' ) ?: 'admin123';
$email = getenv( 'WP_LAB_ADMIN_EMAIL' ) ?: 'admin@example.com';

if ( ! file_exists( $root . '/wp-load.php' ) ) {
	fwrite( STDERR, "WordPress core not found in {$root}\n" );
	exit( 2 );
}

// Satisfy the request globals WordPress expects when running from the CLI.
$host = parse_url( $url, PHP_URL_HOST ) ?: 'localhost';
$_SERVER['HTTP_HOST']   = $_SERVER['HTTP_HOST'] ?? $host;
$_SERVER['SERVER_NAME'] = $_SERVER['SERVER_NAME'] ?? $host;
$_SERVER['REQUEST_URI'] = $_SERVER['REQUEST_URI'] ?? '/';

// wp-load.php bails out with a redirect to /wp-admin/install.php while the site
// is not installed yet (wp_not_installed() at the end of wp-settings.php), which
// would make this script exit silently with code 0. Defining WP_INSTALLING makes
// wp_installing() return true so that wp_not_installed() returns early.
if ( ! defined( 'WP_INSTALLING' ) ) {
	define( 'WP_INSTALLING', true );
}

require_once $root . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';

if ( ! is_blog_installed() ) {
	fwrite( STDOUT, 'Installing WordPress into ' . $root . "...\n" );
	$result = wp_install( $title, $user, $email, true, '', $pass );
	if ( is_wp_error( $result ) ) {
		fwrite( STDERR, 'install failed: ' . $result->get_error_message() . "\n" );
		exit( 3 );
	}
	fwrite( STDOUT, "WordPress installed, admin id={$result['user_id']}\n" );
} else {
	fwrite( STDOUT, "WordPress already installed\n" );
}

// Force the URL the scanner will use and enable pretty permalinks so that
// /?author=1 performs the canonical redirect the scanner looks for.
update_option( 'siteurl', $url );
update_option( 'home', $url );

global $wp_rewrite;
$wp_rewrite->set_permalink_structure( '/%postname%/' );
$wp_rewrite->flush_rules( false );

fwrite( STDOUT, "siteurl={$url} permalinks=/%postname%/\n" );
exit( 0 );
