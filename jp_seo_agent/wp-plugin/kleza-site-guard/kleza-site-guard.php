<?php
/**
 * Plugin Name: Kleza Site Guard
 * Description: File integrity, quarantine and hardening API for the Kleza security agent. Lets an administrator's application password list file checksums and read files (to find backdoors, cloaking code and spam generators) and, for fixes approved in the agent's dashboard, quarantine or replace a file, quarantine an unused plugin or theme, update plugins, themes and core, and switch on hardening (security headers, XML-RPC off, username enumeration blocked, version hidden, security.txt). Every file change keeps the original in a locked quarantine folder so it can be restored; every hardening setting can be turned off again.
 * Version: 1.2.0
 * Requires at least: 5.6
 * Requires PHP: 7.2
 * Author: Kleza
 * License: GPLv2 or later
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'KLEZA_GUARD_VERSION', '1.2.0' );
define( 'KLEZA_GUARD_MAX_WRITE', 5242880 );  // largest file that can be quarantined or replaced
define( 'KLEZA_GUARD_MAX_FILES', 60000 );
define( 'KLEZA_GUARD_MAX_READ', 2097152 );   // 2 MB per file read
define( 'KLEZA_GUARD_MAX_HASH', 5242880 );   // files larger than 5 MB are listed without a checksum

add_action( 'rest_api_init', 'kleza_guard_routes' );

/* ---------------------------------------------------------------------------------------------------------------
 * Hardening (1.2). Settings switched on from the agent's dashboard after a person approves the fix, stored in the
 * kleza_guard_hardening option and applied on every request. Each one can be switched off again (undo).
 *   header:<Name>          send this security header with the given value
 *   remove_header:<Name>   remove a header PHP would send (e.g. X-Powered-By)
 *   disable_xmlrpc         answer xmlrpc.php with 403
 *   block_user_enum        hide /wp/v2/users and ?author=N from visitors who aren't logged in
 *   hide_version           remove the WordPress version from the generator tag and feeds
 *   hide_errors            don't print PHP errors to visitors
 *   security_txt           serve /.well-known/security.txt with this text
 * ------------------------------------------------------------------------------------------------------------- */

function kleza_guard_hardening() {
	$settings = get_option( 'kleza_guard_hardening', array() );
	return is_array( $settings ) ? $settings : array();
}

function kleza_guard_hardening_keys() {
	return array( 'disable_xmlrpc', 'block_user_enum', 'hide_version', 'hide_errors', 'security_txt' );
}

function kleza_guard_valid_key( $key ) {
	if ( in_array( $key, kleza_guard_hardening_keys(), true ) ) {
		return true;
	}
	return (bool) preg_match( '/^(?:header|remove_header):[A-Za-z0-9-]{1,60}$/', $key );
}

function kleza_guard_send_headers() {
	if ( headers_sent() ) {
		return;
	}
	foreach ( kleza_guard_hardening() as $key => $value ) {
		if ( 0 === strpos( $key, 'header:' ) && is_string( $value ) && '' !== $value ) {
			header( substr( $key, 7 ) . ': ' . str_replace( array( "\r", "\n" ), '', $value ) );
		} elseif ( 0 === strpos( $key, 'remove_header:' ) && $value ) {
			header_remove( substr( $key, 14 ) );
		}
	}
}

function kleza_guard_apply_hardening() {
	$h = kleza_guard_hardening();
	if ( ! empty( $h['hide_errors'] ) ) {
		@ini_set( 'display_errors', '0' );
	}
	if ( ! empty( $h['disable_xmlrpc'] ) ) {
		add_filter( 'xmlrpc_enabled', '__return_false' );
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo 'XML-RPC is disabled on this site.';
			exit;
		}
	}
	if ( ! empty( $h['block_user_enum'] ) ) {
		add_filter( 'rest_endpoints', function ( $endpoints ) {
			if ( ! is_user_logged_in() ) {
				foreach ( array_keys( $endpoints ) as $route ) {
					if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
						unset( $endpoints[ $route ] );
					}
				}
			}
			return $endpoints;
		} );
		add_action( 'template_redirect', function () {
			if ( isset( $_GET['author'] ) && ! is_user_logged_in() ) {
				wp_safe_redirect( home_url( '/' ), 301 );
				exit;
			}
		}, 1 );
	}
	if ( ! empty( $h['hide_version'] ) ) {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
	}
	if ( ! empty( $h['security_txt'] ) && is_string( $h['security_txt'] ) ) {
		add_action( 'init', function () use ( $h ) {
			$path = (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH );
			$home = rtrim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
			if ( $path === $home . '/.well-known/security.txt' ) {
				status_header( 200 );
				header( 'Content-Type: text/plain; charset=utf-8' );
				echo $h['security_txt']; // phpcs:ignore WordPress.Security.EscapeOutput -- plain text set by an administrator
				exit;
			}
		}, 0 );
	}
	add_action( 'send_headers', 'kleza_guard_send_headers' );
	add_action( 'login_init', 'kleza_guard_send_headers' );
	add_action( 'admin_init', 'kleza_guard_send_headers' );
}
kleza_guard_apply_hardening();

function kleza_guard_routes() {
	$admin_only = function () {
		return current_user_can( 'manage_options' );
	};
	register_rest_route( 'kleza-guard/v1', '/status', array(
		'methods'             => 'GET',
		'callback'            => 'kleza_guard_status',
		'permission_callback' => $admin_only,
	) );
	register_rest_route( 'kleza-guard/v1', '/files', array(
		'methods'             => 'GET',
		'callback'            => 'kleza_guard_files',
		'permission_callback' => $admin_only,
	) );
	register_rest_route( 'kleza-guard/v1', '/file', array(
		'methods'             => 'GET',
		'callback'            => 'kleza_guard_file',
		'permission_callback' => $admin_only,
		'args'                => array(
			'path' => array( 'required' => true, 'type' => 'string' ),
		),
	) );
	register_rest_route( 'kleza-guard/v1', '/quarantine', array(
		array(
			'methods'             => 'GET',
			'callback'            => 'kleza_guard_quarantine_list',
			'permission_callback' => $admin_only,
		),
		array(
			'methods'             => 'POST',
			'callback'            => 'kleza_guard_quarantine_file',
			'permission_callback' => $admin_only,
			'args'                => array(
				'path'   => array( 'required' => true, 'type' => 'string' ),
				'md5'    => array( 'required' => true, 'type' => 'string' ),
				'reason' => array( 'type' => 'string', 'default' => '' ),
			),
		),
	) );
	register_rest_route( 'kleza-guard/v1', '/replace', array(
		'methods'             => 'POST',
		'callback'            => 'kleza_guard_replace_file',
		'permission_callback' => $admin_only,
		'args'                => array(
			'path'           => array( 'required' => true, 'type' => 'string' ),
			'md5'            => array( 'required' => true, 'type' => 'string' ),
			'content_base64' => array( 'required' => true, 'type' => 'string' ),
			'new_md5'        => array( 'required' => true, 'type' => 'string' ),
			'reason'         => array( 'type' => 'string', 'default' => '' ),
		),
	) );
	register_rest_route( 'kleza-guard/v1', '/hardening', array(
		array(
			'methods'             => 'GET',
			'callback'            => 'kleza_guard_hardening_get',
			'permission_callback' => $admin_only,
		),
		array(
			'methods'             => 'POST',
			'callback'            => 'kleza_guard_hardening_set',
			'permission_callback' => $admin_only,
			'args'                => array(
				'key'   => array( 'required' => true, 'type' => 'string' ),
				'value' => array( 'required' => false ),
			),
		),
	) );
	register_rest_route( 'kleza-guard/v1', '/upgrade', array(
		'methods'             => 'POST',
		'callback'            => 'kleza_guard_upgrade',
		'permission_callback' => function () {
			return current_user_can( 'update_plugins' ) && current_user_can( 'update_themes' );
		},
		'args'                => array(
			'type' => array( 'required' => true, 'type' => 'string', 'enum' => array( 'plugin', 'theme', 'core' ) ),
			'item' => array( 'type' => 'string', 'default' => '' ),
		),
	) );
	register_rest_route( 'kleza-guard/v1', '/quarantine-dir', array(
		'methods'             => 'POST',
		'callback'            => 'kleza_guard_quarantine_dir_route',
		'permission_callback' => $admin_only,
		'args'                => array(
			'path'   => array( 'required' => true, 'type' => 'string' ),
			'reason' => array( 'type' => 'string', 'default' => '' ),
		),
	) );
	register_rest_route( 'kleza-guard/v1', '/restore', array(
		'methods'             => 'POST',
		'callback'            => 'kleza_guard_restore_file',
		'permission_callback' => $admin_only,
		'args'                => array(
			'id'    => array( 'required' => true, 'type' => 'string' ),
			'force' => array( 'type' => 'boolean', 'default' => false ),
		),
	) );
}

/** Site root (ABSPATH) with forward slashes and a trailing slash. */
function kleza_guard_root() {
	return rtrim( str_replace( '\\', '/', realpath( ABSPATH ) ), '/' ) . '/';
}

/** Path relative to the site root, or '' when it lies outside it. */
function kleza_guard_relative( $path ) {
	$root = kleza_guard_root();
	$real = realpath( $path );
	if ( false === $real ) {
		return '';
	}
	$real = rtrim( str_replace( '\\', '/', $real ), '/' ) . '/';
	return 0 === strpos( $real, $root ) ? rtrim( substr( $real, strlen( $root ) ), '/' ) : '';
}

function kleza_guard_status() {
	global $wp_version;
	$uploads = wp_get_upload_dir();
	return array(
		'plugin_version' => KLEZA_GUARD_VERSION,
		'wp_version'     => $wp_version,
		'locale'         => get_locale(),
		'php_version'    => PHP_VERSION,
		'content_dir'    => kleza_guard_relative( WP_CONTENT_DIR ),
		'plugins_dir'    => kleza_guard_relative( WP_PLUGIN_DIR ),
		'mu_plugins_dir' => kleza_guard_relative( WPMU_PLUGIN_DIR ),
		'uploads_dir'    => kleza_guard_relative( $uploads['basedir'] ),
		'themes_dir'     => kleza_guard_relative( get_theme_root() ),
		'stylesheet'     => get_stylesheet(),
		'template'       => get_template(),
		'time'           => time(),
	);
}

/** Inventory of code and web files: path, size, modification time and MD5 (compared with wordpress.org checksums). */
function kleza_guard_files() {
	if ( function_exists( 'set_time_limit' ) ) {
		@set_time_limit( 300 );
	}
	$root     = kleza_guard_root();
	$code_ext = array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'pht', 'phps', 'inc', 'htaccess',
		'ini', 'html', 'htm', 'js', 'ico', 'svg', 'sh', 'pl', 'py', 'cgi', 'suspected' );
	$skip_dir = array( 'node_modules', '.git', '.svn', 'kleza-quarantine' );
	$files    = array();
	$truncated = false;

	$directory = new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS );
	$filtered  = new RecursiveCallbackFilterIterator( $directory, function ( $current ) use ( $skip_dir ) {
		if ( $current->isDir() ) {
			return ! $current->isLink() && ! in_array( $current->getFilename(), $skip_dir, true );
		}
		return true;
	} );
	$iterator = new RecursiveIteratorIterator( $filtered, RecursiveIteratorIterator::LEAVES_ONLY,
		RecursiveIteratorIterator::CATCH_GET_CHILD );

	foreach ( $iterator as $file ) {
		$ext = strtolower( pathinfo( $file->getFilename(), PATHINFO_EXTENSION ) );
		if ( ! in_array( $ext, $code_ext, true ) ) {
			continue;
		}
		$path = str_replace( '\\', '/', $file->getPathname() );
		$rel  = substr( $path, strlen( $root ) );
		// Page caches hold thousands of HTML/JS copies; PHP files in caches are still listed.
		if ( in_array( $ext, array( 'html', 'htm', 'js', 'svg' ), true ) && false !== strpos( $rel, '/cache/' ) ) {
			continue;
		}
		if ( count( $files ) >= KLEZA_GUARD_MAX_FILES ) {
			$truncated = true;
			break;
		}
		$size    = $file->getSize();
		$files[] = array(
			'p' => $rel,
			's' => $size,
			'm' => $file->getMTime(),
			'h' => $size <= KLEZA_GUARD_MAX_HASH ? md5_file( $path ) : null,
		);
	}
	return array( 'files' => $files, 'count' => count( $files ), 'truncated' => $truncated );
}

/** One file's content (base64), at most KLEZA_GUARD_MAX_READ bytes. Secrets in wp-config.php are redacted. */
function kleza_guard_file( WP_REST_Request $request ) {
	$root = kleza_guard_root();
	$rel  = ltrim( str_replace( '\\', '/', (string) $request->get_param( 'path' ) ), '/' );
	$real = realpath( $root . $rel );
	if ( false === $real || ! is_file( $real ) ) {
		return new WP_Error( 'kleza_guard_not_found', 'File not found', array( 'status' => 404 ) );
	}
	$real = str_replace( '\\', '/', $real );
	if ( 0 !== strpos( $real, $root ) ) {
		return new WP_Error( 'kleza_guard_outside', 'The path is outside the site', array( 'status' => 403 ) );
	}
	$size    = filesize( $real );
	$content = file_get_contents( $real, false, null, 0, KLEZA_GUARD_MAX_READ );
	if ( false === $content ) {
		return new WP_Error( 'kleza_guard_unreadable', 'The file could not be read', array( 'status' => 500 ) );
	}
	if ( 'wp-config.php' === basename( $real ) ) {
		$content = kleza_guard_redact( $content );
	}
	return array(
		'path'           => substr( $real, strlen( $root ) ),
		'size'           => $size,
		'mtime'          => filemtime( $real ),
		'md5'            => md5_file( $real ),
		'truncated'      => $size > KLEZA_GUARD_MAX_READ,
		'content_base64' => base64_encode( $content ),
	);
}

/** Replace database credentials, keys and salts in wp-config.php before it leaves the server. */
function kleza_guard_redact( $php ) {
	$names = 'DB_PASSWORD|DB_USER|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT';
	return preg_replace( '/(define\s*\(\s*[\'"](?:' . $names . ')[\'"]\s*,\s*)([\'"]).*?\2/s', '$1$2[redacted]$2', $php );
}

/* ---------------------------------------------------------------------------------------------------------------
 * Quarantine and replace (Phase 2). Every change first copies the original into the quarantine folder
 * (wp-content/kleza-quarantine, web access denied, stored without an executable extension) with a JSON manifest,
 * and checks the file's MD5 against what the agent saw, so a file that changed since the scan is never touched.
 * ------------------------------------------------------------------------------------------------------------- */

function kleza_guard_quarantine_dir() {
	$dir = rtrim( str_replace( '\\', '/', WP_CONTENT_DIR ), '/' ) . '/kleza-quarantine';
	if ( ! is_dir( $dir ) ) {
		wp_mkdir_p( $dir );
	}
	if ( ! file_exists( $dir . '/.htaccess' ) ) {
		file_put_contents( $dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
	}
	if ( ! file_exists( $dir . '/index.php' ) ) {
		file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" );
	}
	return $dir;
}

/** Resolve a site-relative path to a real file the agent may change, or a WP_Error. */
function kleza_guard_target( $rel ) {
	$root = kleza_guard_root();
	$rel  = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
	$real = realpath( $root . $rel );
	if ( false === $real || ! is_file( $real ) ) {
		return new WP_Error( 'kleza_guard_not_found', 'File not found', array( 'status' => 404 ) );
	}
	$real   = str_replace( '\\', '/', $real );
	$plugin = str_replace( '\\', '/', plugin_dir_path( __FILE__ ) );
	if ( 0 !== strpos( $real, $root ) ) {
		return new WP_Error( 'kleza_guard_outside', 'The path is outside the site', array( 'status' => 403 ) );
	}
	if ( 'wp-config.php' === basename( $real ) || 0 === strpos( $real, $plugin )
		|| 0 === strpos( $real, kleza_guard_quarantine_dir() . '/' ) ) {
		return new WP_Error( 'kleza_guard_protected', 'This file is never changed automatically', array( 'status' => 403 ) );
	}
	if ( filesize( $real ) > KLEZA_GUARD_MAX_WRITE ) {
		return new WP_Error( 'kleza_guard_too_large', 'The file is too large', array( 'status' => 413 ) );
	}
	return array( 'real' => $real, 'path' => substr( $real, strlen( $root ) ) );
}

function kleza_guard_manifest_path( $id ) {
	return kleza_guard_quarantine_dir() . '/' . $id . '.json';
}

function kleza_guard_save_manifest( $entry ) {
	return false !== file_put_contents( kleza_guard_manifest_path( $entry['id'] ), wp_json_encode( $entry, JSON_PRETTY_PRINT ) );
}

/** Copy the original into the quarantine folder and record it. Returns the manifest entry or a WP_Error. */
function kleza_guard_stash( $file, $action, $reason ) {
	$id   = bin2hex( random_bytes( 16 ) );
	$copy = kleza_guard_quarantine_dir() . '/' . $id . '.bin';
	$md5  = md5_file( $file['real'] );
	if ( ! @copy( $file['real'], $copy ) || md5_file( $copy ) !== $md5 ) {
		@unlink( $copy );
		return new WP_Error( 'kleza_guard_backup_failed', 'Could not copy the original into quarantine', array( 'status' => 500 ) );
	}
	$user  = wp_get_current_user();
	$entry = array(
		'id'     => $id,
		'path'   => $file['path'],
		'action' => $action,
		'reason' => substr( sanitize_text_field( $reason ), 0, 300 ),
		'md5'    => $md5,
		'size'   => filesize( $file['real'] ),
		'mtime'  => filemtime( $file['real'] ),
		'perms'  => fileperms( $file['real'] ) & 0777,
		'time'   => time(),
		'by'     => $user ? $user->user_login : '',
		'status' => 'pending',
	);
	if ( ! kleza_guard_save_manifest( $entry ) ) {
		@unlink( $copy );
		return new WP_Error( 'kleza_guard_backup_failed', 'Could not write the quarantine record', array( 'status' => 500 ) );
	}
	return $entry;
}

/** Write content to a path through a temporary file and a rename, keeping the permissions. */
function kleza_guard_write( $real, $content, $perms ) {
	$tmp = $real . '.kleza-tmp';
	if ( false === file_put_contents( $tmp, $content ) ) {
		return false;
	}
	@chmod( $tmp, $perms ? $perms : 0644 );
	if ( ! @rename( $tmp, $real ) ) {
		@unlink( $tmp );
		return false;
	}
	return true;
}

function kleza_guard_quarantine_list() {
	$entries = array();
	foreach ( (array) glob( kleza_guard_quarantine_dir() . '/*.json' ) as $file ) {
		$entry = json_decode( (string) file_get_contents( $file ), true );
		if ( is_array( $entry ) ) {
			$entries[] = $entry;
		}
	}
	usort( $entries, function ( $a, $b ) {
		return $b['time'] - $a['time'];
	} );
	return array( 'entries' => $entries );
}

/** Move a file into quarantine (it disappears from its path). */
function kleza_guard_quarantine_file( WP_REST_Request $request ) {
	$file = kleza_guard_target( $request->get_param( 'path' ) );
	if ( is_wp_error( $file ) ) {
		return $file;
	}
	if ( md5_file( $file['real'] ) !== $request->get_param( 'md5' ) ) {
		return new WP_Error( 'kleza_guard_changed', 'The file changed since the scan; scan again first', array( 'status' => 409 ) );
	}
	$entry = kleza_guard_stash( $file, 'quarantine', $request->get_param( 'reason' ) );
	if ( is_wp_error( $entry ) ) {
		return $entry;
	}
	if ( ! @unlink( $file['real'] ) ) {
		@unlink( kleza_guard_quarantine_dir() . '/' . $entry['id'] . '.bin' );
		@unlink( kleza_guard_manifest_path( $entry['id'] ) );
		return new WP_Error( 'kleza_guard_write_failed', 'Could not remove the file (permissions?)', array( 'status' => 500 ) );
	}
	$entry['status'] = 'quarantined';
	kleza_guard_save_manifest( $entry );
	return $entry;
}

/** Replace a file's content (e.g. with the official WordPress copy), keeping the original in quarantine. */
function kleza_guard_replace_file( WP_REST_Request $request ) {
	$file = kleza_guard_target( $request->get_param( 'path' ) );
	if ( is_wp_error( $file ) ) {
		return $file;
	}
	if ( md5_file( $file['real'] ) !== $request->get_param( 'md5' ) ) {
		return new WP_Error( 'kleza_guard_changed', 'The file changed since the scan; scan again first', array( 'status' => 409 ) );
	}
	$content = base64_decode( (string) $request->get_param( 'content_base64' ), true );
	if ( false === $content || md5( $content ) !== $request->get_param( 'new_md5' ) ) {
		return new WP_Error( 'kleza_guard_bad_content', 'The new content does not match its checksum', array( 'status' => 400 ) );
	}
	$entry = kleza_guard_stash( $file, 'replace', $request->get_param( 'reason' ) );
	if ( is_wp_error( $entry ) ) {
		return $entry;
	}
	if ( ! kleza_guard_write( $file['real'], $content, $entry['perms'] ) || md5_file( $file['real'] ) !== md5( $content ) ) {
		return new WP_Error( 'kleza_guard_write_failed', 'Could not write the file (permissions?)', array( 'status' => 500 ) );
	}
	$entry['status']  = 'replaced';
	$entry['new_md5'] = md5( $content );
	kleza_guard_save_manifest( $entry );
	return $entry;
}

/** Put a quarantined or replaced file back exactly as it was. */
function kleza_guard_restore_file( WP_REST_Request $request ) {
	$id = (string) $request->get_param( 'id' );
	if ( ! preg_match( '/^[a-f0-9]{32}$/', $id ) || ! is_file( kleza_guard_manifest_path( $id ) ) ) {
		return new WP_Error( 'kleza_guard_unknown', 'Unknown quarantine entry', array( 'status' => 404 ) );
	}
	$entry = json_decode( (string) file_get_contents( kleza_guard_manifest_path( $id ) ), true );
	$copy  = kleza_guard_quarantine_dir() . '/' . $id . '.bin';
	if ( is_array( $entry ) && ! empty( $entry['dir'] ) ) {
		return kleza_guard_restore_dir( $entry );
	}
	if ( ! is_array( $entry ) || ! is_file( $copy ) || md5_file( $copy ) !== $entry['md5'] ) {
		return new WP_Error( 'kleza_guard_corrupt', 'The quarantined copy is missing or damaged', array( 'status' => 500 ) );
	}
	$real = kleza_guard_root() . $entry['path'];
	if ( ! $request->get_param( 'force' ) && file_exists( $real ) ) {
		$current = md5_file( $real );
		$ours    = isset( $entry['new_md5'] ) ? $entry['new_md5'] : null;
		if ( $current !== $ours && $current !== $entry['md5'] ) {
			return new WP_Error( 'kleza_guard_changed', 'The file changed after the fix; restore with force to overwrite it', array( 'status' => 409 ) );
		}
	}
	if ( ! is_dir( dirname( $real ) ) ) {
		wp_mkdir_p( dirname( $real ) );
	}
	if ( ! kleza_guard_write( $real, file_get_contents( $copy ), $entry['perms'] ) || md5_file( $real ) !== $entry['md5'] ) {
		return new WP_Error( 'kleza_guard_write_failed', 'Could not restore the file (permissions?)', array( 'status' => 500 ) );
	}
	@touch( $real, $entry['mtime'] );
	$entry['status']      = 'restored';
	$entry['restored_at'] = time();
	kleza_guard_save_manifest( $entry );
	return $entry;
}

/* ---------------------------------------------------------------------------------------------------------------
 * Hardening, updates and folder quarantine (1.2): the endpoints behind the agent's approved security fixes.
 * ------------------------------------------------------------------------------------------------------------- */

function kleza_guard_hardening_get() {
	return array( 'settings' => kleza_guard_hardening(), 'plugin_version' => KLEZA_GUARD_VERSION );
}

/** Set one hardening setting (a null, false or empty value removes it). Returns the previous value for undo. */
function kleza_guard_hardening_set( WP_REST_Request $request ) {
	$key = (string) $request->get_param( 'key' );
	if ( ! kleza_guard_valid_key( $key ) ) {
		return new WP_Error( 'kleza_guard_bad_key', 'Unknown hardening setting', array( 'status' => 400 ) );
	}
	$value    = $request->get_param( 'value' );
	$settings = kleza_guard_hardening();
	$previous = array_key_exists( $key, $settings ) ? $settings[ $key ] : null;
	if ( null === $value || false === $value || '' === $value ) {
		unset( $settings[ $key ] );
	} elseif ( is_string( $value ) ) {
		$settings[ $key ] = substr( str_replace( "\r", '', $value ), 0, 2000 );
	} else {
		$settings[ $key ] = (bool) $value;
	}
	update_option( 'kleza_guard_hardening', $settings, true );
	return array( 'key' => $key, 'previous' => $previous, 'settings' => $settings );
}

function kleza_guard_upgrader_includes() {
	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/misc.php';
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	require_once ABSPATH . 'wp-admin/includes/theme.php';
	require_once ABSPATH . 'wp-admin/includes/update.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
}

/** Update one plugin (its folder name), one theme (stylesheet) or WordPress core to the latest release. */
function kleza_guard_upgrade( WP_REST_Request $request ) {
	if ( function_exists( 'set_time_limit' ) ) {
		@set_time_limit( 600 );
	}
	kleza_guard_upgrader_includes();
	if ( ! WP_Filesystem() ) {
		return new WP_Error( 'kleza_guard_fs', 'WordPress needs FTP credentials to update files on this server', array( 'status' => 500 ) );
	}
	$type = $request->get_param( 'type' );
	$item = (string) $request->get_param( 'item' );
	$skin = new Automatic_Upgrader_Skin();
	if ( 'plugin' === $type ) {
		$file = '';
		foreach ( array_keys( get_plugins() ) as $plugin_file ) {
			if ( strtok( $plugin_file, '/' ) === $item || $plugin_file === $item ) {
				$file = $plugin_file;
				break;
			}
		}
		if ( '' === $file ) {
			return new WP_Error( 'kleza_guard_unknown', 'Plugin not installed', array( 'status' => 404 ) );
		}
		$before = get_plugin_data( WP_PLUGIN_DIR . '/' . $file, false, false );
		$active = is_plugin_active( $file );
		wp_update_plugins();
		$result = ( new Plugin_Upgrader( $skin ) )->upgrade( $file );
		if ( $active && ! is_plugin_active( $file ) ) {
			activate_plugin( $file );
		}
		wp_clean_plugins_cache();
		$after = get_plugin_data( WP_PLUGIN_DIR . '/' . $file, false, false );
		$from  = $before['Version'];
		$to    = $after['Version'];
	} elseif ( 'theme' === $type ) {
		$theme = wp_get_theme( $item );
		if ( ! $theme->exists() ) {
			return new WP_Error( 'kleza_guard_unknown', 'Theme not installed', array( 'status' => 404 ) );
		}
		$from = $theme->get( 'Version' );
		wp_update_themes();
		$result = ( new Theme_Upgrader( $skin ) )->upgrade( $item );
		wp_clean_themes_cache();
		$to = wp_get_theme( $item )->get( 'Version' );
	} else {
		global $wp_version;
		$from = $wp_version;
		wp_version_check( array(), true );
		$update = get_preferred_from_update_core();
		if ( ! $update || 'latest' === $update->response ) {
			return array( 'type' => $type, 'item' => 'core', 'from' => $from, 'to' => $from, 'updated' => false );
		}
		$result = ( new Core_Upgrader( $skin ) )->upgrade( $update );
		$to     = is_string( $result ) ? $result : $from;
	}
	if ( is_wp_error( $result ) ) {
		return new WP_Error( 'kleza_guard_upgrade_failed', $result->get_error_message(), array( 'status' => 500 ) );
	}
	if ( false === $result || null === $result ) {
		$messages = implode( ' ', array_map( 'wp_strip_all_tags', (array) $skin->get_upgrade_messages() ) );
		return new WP_Error( 'kleza_guard_upgrade_failed', trim( 'The update did not run. ' . substr( $messages, -300 ) ), array( 'status' => 500 ) );
	}
	return array( 'type' => $type, 'item' => $item ? $item : 'core', 'from' => $from, 'to' => $to,
		'updated' => $from !== $to );
}

/** Move an unused plugin or theme folder into quarantine (restorable with /restore). */
function kleza_guard_quarantine_dir_route( WP_REST_Request $request ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	$root = kleza_guard_root();
	$rel  = trim( str_replace( '\\', '/', (string) $request->get_param( 'path' ) ), '/' );
	$real = realpath( $root . $rel );
	if ( false === $real || ! is_dir( $real ) ) {
		return new WP_Error( 'kleza_guard_not_found', 'Folder not found', array( 'status' => 404 ) );
	}
	$real    = rtrim( str_replace( '\\', '/', $real ), '/' );
	$plugins = rtrim( str_replace( '\\', '/', realpath( WP_PLUGIN_DIR ) ), '/' );
	$themes  = rtrim( str_replace( '\\', '/', realpath( get_theme_root() ) ), '/' );
	$parent  = dirname( $real );
	$name    = basename( $real );
	if ( $parent !== $plugins && $parent !== $themes ) {
		return new WP_Error( 'kleza_guard_protected', 'Only a plugin or theme folder can be quarantined', array( 'status' => 403 ) );
	}
	if ( rtrim( str_replace( '\\', '/', plugin_dir_path( __FILE__ ) ), '/' ) === $real ) {
		return new WP_Error( 'kleza_guard_protected', 'The Site Guard plugin is never quarantined', array( 'status' => 403 ) );
	}
	if ( $parent === $plugins ) {
		foreach ( array_keys( get_plugins() ) as $plugin_file ) {
			if ( strtok( $plugin_file, '/' ) === $name && ( is_plugin_active( $plugin_file ) || is_plugin_active_for_network( $plugin_file ) ) ) {
				return new WP_Error( 'kleza_guard_active', 'The plugin is active; deactivate it first', array( 'status' => 409 ) );
			}
		}
	} elseif ( in_array( $name, array( get_stylesheet(), get_template() ), true ) ) {
		return new WP_Error( 'kleza_guard_active', 'The theme is in use', array( 'status' => 409 ) );
	}
	$id     = bin2hex( random_bytes( 16 ) );
	$target = kleza_guard_quarantine_dir() . '/' . $id . '.dir';
	if ( ! @rename( $real, $target ) ) {
		return new WP_Error( 'kleza_guard_write_failed', 'Could not move the folder (permissions?)', array( 'status' => 500 ) );
	}
	$user  = wp_get_current_user();
	$entry = array(
		'id'     => $id,
		'path'   => substr( $real, strlen( $root ) ),
		'dir'    => true,
		'action' => 'quarantine-dir',
		'reason' => substr( sanitize_text_field( (string) $request->get_param( 'reason' ) ), 0, 300 ),
		'time'   => time(),
		'by'     => $user ? $user->user_login : '',
		'status' => 'quarantined',
	);
	kleza_guard_save_manifest( $entry );
	if ( $parent === $plugins ) {
		wp_clean_plugins_cache();
	} else {
		wp_clean_themes_cache();
	}
	return $entry;
}

function kleza_guard_restore_dir( $entry ) {
	$source = kleza_guard_quarantine_dir() . '/' . $entry['id'] . '.dir';
	$real   = kleza_guard_root() . $entry['path'];
	if ( ! is_dir( $source ) ) {
		return new WP_Error( 'kleza_guard_corrupt', 'The quarantined folder is missing', array( 'status' => 500 ) );
	}
	if ( file_exists( $real ) ) {
		return new WP_Error( 'kleza_guard_changed', 'A folder with that name exists again', array( 'status' => 409 ) );
	}
	if ( ! @rename( $source, $real ) ) {
		return new WP_Error( 'kleza_guard_write_failed', 'Could not restore the folder (permissions?)', array( 'status' => 500 ) );
	}
	$entry['status']      = 'restored';
	$entry['restored_at'] = time();
	kleza_guard_save_manifest( $entry );
	return $entry;
}
