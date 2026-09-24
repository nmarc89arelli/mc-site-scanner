<?php
/**
 * Plugin Name: Relish Security
 * Description: Malware and integrity scanner, rendered-page and vulnerability checks, instant alerts, activity log, central reporting, one-click repair and quarantine, hardening switches and incident response tools. Scanning is read-only and runs in small timed batches. Anything that changes the site only runs when you press it, and is verified and rolled back if the site stops responding.
 * Version: 1.6.0
 * Author: Marcarelli Consulting
 * Requires PHP: 7.4
 * Requires at least: 5.8
 * License: GPL2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'MCSS_Scanner' ) ) :

define( 'MCSS_FILE', __FILE__ );
// Ed25519 public key. Releases and rules.dat are signed with the matching private key, which lives only on the release machine.
define( 'MCSS_PUBKEY', '__MCSS_PUBKEY__' );

final class MCSS_Scanner {

	const VERSION      = '1.6.0';
	const OPT_STATE    = 'mcss_state';
	const OPT_FINDINGS = 'mcss_findings';
	const OPT_RUN      = 'mcss_findings_run';
	const OPT_IGNORED  = 'mcss_ignored';
	const OPT_BASELINE = 'mcss_baseline';
	const OPT_SETTINGS = 'mcss_settings';
	const OPT_LAST     = 'mcss_last';
	const OPT_SALTS    = 'mcss_salts_rotated';
	const CHUNK        = 1500;
	const MAX_READ     = 1500000;
	const MAX_FINDINGS = 1500;

	private static $findings = null;
	private static $rule_counts = array();
	private static $dirty = false;
	private static $dropped = 0;
	private static $chunk_cache = array( 'i' => -1, 'd' => array() );

	/* ---------------------------------------------------------------------
	 * Bootstrap
	 * ------------------------------------------------------------------- */

	public static function init() {
		add_action( 'wp_ajax_mcss_start', array( __CLASS__, 'ajax_start' ) );
		add_action( 'wp_ajax_mcss_step', array( __CLASS__, 'ajax_step' ) );
		add_action( 'wp_ajax_mcss_ignore', array( __CLASS__, 'ajax_ignore' ) );
		add_action( 'wp_ajax_mcss_rotate_salts', array( __CLASS__, 'ajax_rotate_salts' ) );
		add_action( 'wp_ajax_mcss_reset_admins', array( __CLASS__, 'ajax_reset_admins' ) );
		add_action( 'wp_ajax_mcss_logout_all', array( __CLASS__, 'ajax_logout_all' ) );
		add_action( 'admin_post_mcss_report', array( __CLASS__, 'download_report' ) );
		add_action( 'admin_post_mcss_reset_ignored', array( __CLASS__, 'reset_ignored' ) );
		add_action( 'mcss_daily_scan', array( __CLASS__, 'cron_start' ) );
		add_action( 'mcss_continue', array( __CLASS__, 'cron_continue' ) );
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( 'mcss_daily_scan' );
		wp_clear_scheduled_hook( 'mcss_continue' );
		wp_clear_scheduled_hook( 'mcss_watch' );
	}

	public static function uninstall() {
		global $wpdb;
		self::deactivate();
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'mcss\_%'" );
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'mcss_log' );
		$cfg = self::config_path();
		if ( $cfg !== '' ) {
			foreach ( (array) glob( dirname( $cfg ) . '/wp-config-backup-mcss-*.php' ) as $f ) {
				if ( preg_match( '~/wp-config-backup-mcss-\d{8}-\d{6}-[a-z0-9]{10}\.php$~', self::norm( $f ) ) ) {
					@unlink( $f );
				}
			}
		}
	}

	public static function settings() {
		$s = get_option( self::OPT_SETTINGS, array() );
		if ( ! is_array( $s ) ) {
			$s = array();
		}
		return array_merge(
			array(
				'daily'         => 0,
				'email'         => get_option( 'admin_email' ),
				'alert_admins'  => 1,
				'alert_plugins' => 1,
				'alert_files'   => 1,
				'render'        => 1,
				'render_urls'   => '',
				'vuln'          => 1,
				'webhook'       => '',
				'secret'        => '',
				'log_days'      => 90,
				'h_file_edit'   => 0,
				'h_xmlrpc'      => 0,
				'h_enum'        => 0,
				'h_app_pw'      => 0,
				'h_version'     => 0,
				'h_headers'     => 0,
				'h_uploads'     => 0,
				'auto_update'   => 0,
			),
			$s
		);
	}

	/* ---------------------------------------------------------------------
	 * Path helpers
	 * ------------------------------------------------------------------- */

	public static function norm( $p ) {
		return str_replace( '\\', '/', (string) $p );
	}

	private static function base() {
		return rtrim( self::norm( ABSPATH ), '/' ) . '/';
	}

	public static function rel( $abs ) {
		$abs  = self::norm( $abs );
		$base = self::base();
		if ( strpos( $abs, $base ) === 0 ) {
			return substr( $abs, strlen( $base ) );
		}
		return $abs;
	}

	public static function abs( $rel ) {
		if ( $rel !== '' && ( $rel[0] === '/' || preg_match( '~^[A-Za-z]:/~', $rel ) ) ) {
			return $rel;
		}
		return self::base() . $rel;
	}

	public static function ext( $path ) {
		return strtolower( (string) pathinfo( $path, PATHINFO_EXTENSION ) );
	}

	public static function is_php_ext( $ext ) {
		static $e = array( 'php' => 1, 'php3' => 1, 'php4' => 1, 'php5' => 1, 'php6' => 1, 'php7' => 1, 'php8' => 1, 'phtml' => 1, 'phtm' => 1, 'pht' => 1, 'phps' => 1, 'pgif' => 1, 'phar' => 1, 'inc' => 1, 'suspected' => 1 );
		return isset( $e[ $ext ] );
	}

	public static function uploads_rel() {
		$u = wp_upload_dir( null, false );
		return rtrim( self::rel( isset( $u['basedir'] ) ? $u['basedir'] : WP_CONTENT_DIR . '/uploads' ), '/' ) . '/';
	}

	public static function under( $rel, $dir_rel ) {
		return strpos( $rel, $dir_rel ) === 0;
	}

	/* ---------------------------------------------------------------------
	 * Rules
	 * ------------------------------------------------------------------- */

	/**
	 * Detection signatures live in rules.dat, not in this file, and are stored letter-rotated. A plain list of web shell
	 * names and payload patterns makes antivirus products, hosts and chat apps flag the scanner itself as malware.
	 * Security vendors ship their signatures encoded for the same reason. Nothing in rules.dat is executed: it is JSON.
	 */
	private static $rules = null;

	/** Fingerprint of the scanner's own code and signatures, sent with every heartbeat so a central dashboard can spot a modified copy. */
	public static function self_hash() {
		return hash( 'sha256', (string) @hash_file( 'sha256', MCSS_FILE ) . '|' . (string) @hash_file( 'sha256', self::rules_file() ) );
	}

	public static function rules_file() {
		return dirname( MCSS_FILE ) . '/rules.dat';
	}

	public static function rules() {
		if ( self::$rules === null ) {
			$raw  = @file_get_contents( self::rules_file() );
			$data = is_string( $raw ) ? json_decode( str_rot13( $raw ), true ) : null;
			$ok   = is_array( $data ) && ! empty( $data['php'] ) && ! empty( $data['named'] );
			self::$rules = $ok ? $data : array( 'php' => array(), 'js' => array(), 'conf' => array(), 'named' => array(), 'spam' => array(), 'needles' => array(), 'missing' => true );
		}
		return self::$rules;
	}

	private static function named( $key ) {
		$r = self::rules();
		return isset( $r['named'][ $key ] ) ? $r['named'][ $key ] : '~(?!)~';
	}

	private static function php_rules() {
		$r = self::rules();
		return apply_filters( 'mcss_php_rules', $r['php'] );
	}

	private static function js_rules() {
		$r = self::rules();
		return apply_filters( 'mcss_js_rules', $r['js'] );
	}

	private static function conf_rules() {
		$r = self::rules();
		return $r['conf'];
	}

	/* ---------------------------------------------------------------------
	 * Findings
	 * ------------------------------------------------------------------- */

	public static function load_findings() {
		if ( self::$findings === null ) {
			$f = get_option( self::OPT_RUN, array() );
			self::$findings    = is_array( $f ) ? $f : array();
			self::$rule_counts = array();
			foreach ( self::$findings as $x ) {
				self::$rule_counts[ $x['rule'] ] = isset( self::$rule_counts[ $x['rule'] ] ) ? self::$rule_counts[ $x['rule'] ] + 1 : 1;
			}
		}
	}

	/**
	 * Record a finding. $disc separates findings that share a rule and a path (one per domain, per version and so on),
	 * so one can never hide another. On a true duplicate the higher severity wins. High findings are never dropped.
	 */
	public static function add( $sev, $rule, $title, $path = '', $line = 0, $snip = '', $note = '', $disc = '' ) {
		self::load_findings();
		$total = count( self::$findings );
		if ( $sev !== 'high' && ( $total >= self::MAX_FINDINGS || ( isset( self::$rule_counts[ $rule ] ) && self::$rule_counts[ $rule ] >= 150 ) ) ) {
			self::$dropped++;
			return;
		}
		if ( $total >= 4 * self::MAX_FINDINGS ) {
			self::$dropped++;
			return;
		}
		$hash = '';
		$mt   = 0;
		if ( $path !== '' && strpos( $path, ':' ) === false ) {
			$abs = self::abs( $path );
			if ( is_file( $abs ) && is_readable( $abs ) ) {
				$hash = (string) @md5_file( $abs );
				$mt   = (int) @filemtime( $abs );
			}
			if ( preg_match( '~^wp-config~i', basename( $path ) ) ) {
				$snip = ''; // Never copy lines out of a config file: they can hold the database password or salts.
			}
		}
		$key   = md5( $rule . '|' . $path . '|' . $hash . '|' . $disc );
		$order = array( 'low' => 1, 'medium' => 2, 'high' => 3 );
		if ( isset( self::$findings[ $key ] ) ) {
			$old = self::$findings[ $key ]['sev'];
			if ( ( isset( $order[ $sev ] ) ? $order[ $sev ] : 0 ) <= ( isset( $order[ $old ] ) ? $order[ $old ] : 0 ) ) {
				return;
			}
		}
		self::$rule_counts[ $rule ] = isset( self::$rule_counts[ $rule ] ) ? self::$rule_counts[ $rule ] + 1 : 1;
		self::$dirty                = true;
		self::$findings[ $key ]     = array(
			'k'     => $key,
			'sev'   => $sev,
			'rule'  => $rule,
			'title' => $title,
			'path'  => $path,
			'line'  => (int) $line,
			'snip'  => $snip,
			'note'  => $note,
			'mt'    => $mt,
		);
	}

	public static function save_findings() {
		if ( self::$findings !== null && self::$dirty ) {
			update_option( self::OPT_RUN, self::$findings, false );
			self::$dirty = false;
		}
	}

	public static function clean_snip( $s ) {
		$s = preg_replace( '~[\x00-\x1F\x7F]+~', ' ', (string) $s );
		$s = function_exists( 'wp_check_invalid_utf8' ) ? wp_check_invalid_utf8( $s, true ) : $s;
		return trim( preg_replace( '~\s{2,}~', ' ', (string) $s ) );
	}

	/* ---------------------------------------------------------------------
	 * Scan lifecycle
	 * ------------------------------------------------------------------- */

	public static function state() {
		$s = get_option( self::OPT_STATE, array() );
		return is_array( $s ) ? $s : array();
	}

	private static function save_state( $state ) {
		$state['updated'] = time();
		update_option( self::OPT_STATE, $state, false );
	}

	private static function cleanup_chunks( $state ) {
		if ( empty( $state['id'] ) ) {
			return;
		}
		$n = isset( $state['list_chunks'] ) ? (int) $state['list_chunks'] : 0;
		for ( $i = 0; $i < $n; $i++ ) {
			delete_option( 'mcss_' . $state['id'] . '_list_' . $i );
		}
		delete_option( 'mcss_' . $state['id'] . '_buf' );
		$n = isset( $state['verified_chunks'] ) ? (int) $state['verified_chunks'] : 0;
		for ( $i = 0; $i < $n; $i++ ) {
			delete_option( 'mcss_' . $state['id'] . '_ver_' . $i );
		}
	}

	/** Capability for every screen and action. On multisite the scanner reads and changes network-wide files, so only super admins qualify. */
	public static function cap() {
		return is_multisite() ? 'manage_network' : 'manage_options';
	}

	/** Atomic lock straight in the database, so a persistent object cache cannot hand two requests the same lock. */
	public static function lock() {
		global $wpdb;
		$now = time();
		$old = $wpdb->suppress_errors( true );
		$wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES ('mcss_lock', %s, 'no')", $now ) );
		$got = ( 1 === (int) $wpdb->rows_affected );
		if ( ! $got ) {
			$t = (int) $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name = 'mcss_lock'" );
			if ( $t < $now - 150 ) {
				$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = 'mcss_lock' AND option_value = %s", $now, $t ) );
				$got = ( 1 === (int) $wpdb->rows_affected );
			}
		}
		$wpdb->suppress_errors( $old );
		return $got;
	}

	public static function unlock() {
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name = 'mcss_lock'" );
	}

	public static function start( $mode ) {
		self::cleanup_chunks( self::state() );
		delete_transient( 'mcss_core_sums' );

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$queue = array();
		$own   = basename( dirname( __FILE__ ) );
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( $slug === '.' || $slug === '' || $slug === $own || isset( $queue[ $slug ] ) ) {
				continue;
			}
			$queue[ $slug ] = isset( $data['Version'] ) ? (string) $data['Version'] : '';
		}

		$state = array(
			'id'              => substr( md5( uniqid( '', true ) ), 0, 8 ),
			'mode'            => $mode,
			'phase'           => 'core',
			'offset'          => 0,
			'started'         => time(),
			'marker'          => '',
			'attempts'        => 0,
			'plugins_queue'   => $queue,
			'plugins_total'   => count( $queue ),
			'plugins_status'  => array(),
			'mismatch'        => array(),
			'dir_stack'       => null,
			'symlinks'        => 0,
			'list_chunks'     => 0,
			'verified_chunks' => 0,
			'total_files'     => 0,
			'core_total'      => 0,
			'db_step'         => 0,
			'db_cur'          => 0,
			'db_max'          => -1,
			'db_seen'         => 0,
			'domains'         => array(),
			'render_queue'    => null,
			'render_sum'      => array(),
			'render_domains'  => array(),
			'vuln_queue'      => null,
			'vuln_total'      => 0,
			'inventory'       => array(),
			'notes'           => array(),
			'done'            => false,
		);
		self::$findings    = array();
		self::$rule_counts = array();
		self::$dirty       = false;
		self::$dropped     = 0;
		$rules             = self::rules();
		if ( ! empty( $rules['missing'] ) ) {
			$state['notes'][] = 'rules.dat is missing or unreadable, so NO file, database or page patterns were checked in this scan. Reinstall the plugin from its zip. Checksums, users, the file watch and the vulnerability check still ran.';
		}
		update_option( self::OPT_RUN, array(), false );
		self::save_state( $state );
		return $state;
	}

	private static function marker( $state ) {
		return implode(
			'|',
			array(
				$state['phase'],
				(int) $state['offset'],
				(int) $state['db_step'],
				(int) $state['db_cur'],
				count( (array) $state['plugins_queue'] ),
				is_array( $state['dir_stack'] ) ? count( $state['dir_stack'] ) . ':' . (int) $state['total_files'] : 'x',
				is_array( $state['render_queue'] ) ? count( $state['render_queue'] ) : 'x',
				is_array( $state['vuln_queue'] ) ? count( $state['vuln_queue'] ) : 'x',
			)
		);
	}

	/** A step that died (timeout, memory) leaves its marker behind. After three tries at the same spot, step over it. */
	private static function skip_stuck( $state ) {
		$phase = $state['phase'];
		if ( $phase === 'files' ) {
			$rel              = self::list_item( $state, (int) $state['offset'] );
			$state['notes'][] = 'Scanning stopped three times on ' . ( $rel !== null ? $rel : 'one file' ) . ', so that file was skipped. Look at it by hand.';
			$state['offset']  = (int) $state['offset'] + 1;
		} elseif ( $phase === 'list' && is_array( $state['dir_stack'] ) && ! empty( $state['dir_stack'] ) ) {
			$dir              = array_pop( $state['dir_stack'] );
			$state['notes'][] = 'Listing stopped three times in ' . self::rel( preg_replace( '~^R\|~', '', $dir ) ) . ', so that folder was skipped. It may be too large to read in one request.';
		} elseif ( $phase === 'db' ) {
			$state['notes'][] = 'A database range could not be read three times in a row and was skipped.';
			$state['db_cur']  = (int) $state['db_cur'] + 20000;
		} else {
			$order            = array( 'core' => 'plugins', 'plugins' => 'list', 'list' => 'files', 'render' => 'vuln', 'vuln' => 'checks', 'checks' => 'finish' );
			$state['notes'][] = 'The "' . $phase . '" part of the scan failed three times and was skipped.';
			$state['phase']   = isset( $order[ $phase ] ) ? $order[ $phase ] : 'finish';
			$state['offset']  = 0;
		}
		$state['attempts'] = 0;
		$state['marker']   = '';
		return $state;
	}

	/**
	 * Advance the scan for at most $budget seconds. Safe to call repeatedly. The caller holds the lock.
	 */
	public static function step( $budget ) {
		$state = self::state();
		if ( empty( $state ) || ! empty( $state['done'] ) ) {
			return $state;
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( (int) $budget + 60 );
		}

		// A scan begun by an older version of the plugin lacks the newer keys. Give them safe defaults.
		$state += array( 'marker' => '', 'attempts' => 0, 'dir_stack' => null, 'symlinks' => 0, 'db_cur' => 0, 'db_max' => -1, 'db_seen' => 0, 'render_queue' => null, 'render_sum' => array(), 'render_domains' => array(), 'vuln_queue' => null, 'vuln_total' => 0 );

		$marker = self::marker( $state );
		if ( $state['marker'] === $marker ) {
			$state['attempts'] = (int) $state['attempts'] + 1;
		} else {
			$state['attempts'] = 1;
			$state['marker']   = $marker;
		}
		if ( $state['attempts'] > 3 ) {
			$state = self::skip_stuck( $state );
		}
		self::save_state( $state );

		$deadline = microtime( true ) + $budget;
		self::load_findings();

		while ( empty( $state['done'] ) && microtime( true ) < $deadline ) {
			$phase = $state['phase'];
			try {
				switch ( $phase ) {
					case 'core':
						$state = self::phase_core( $state, $deadline );
						break;
					case 'plugins':
						$state = self::phase_plugins( $state, $deadline );
						break;
					case 'list':
						$state = self::phase_list( $state, $deadline );
						break;
					case 'files':
						$state = self::phase_files( $state, $deadline );
						break;
					case 'db':
						$state = self::phase_db( $state, $deadline );
						break;
					case 'render':
						$state = self::phase_render( $state, $deadline );
						break;
					case 'vuln':
						$state = self::phase_vuln( $state, $deadline );
						break;
					case 'checks':
						$state = self::phase_checks( $state );
						break;
					default:
						$state = self::finish( $state );
				}
			} catch ( \Throwable $e ) {
				$state['notes'][] = 'Phase "' . $phase . '" stopped early: ' . $e->getMessage();
				$order            = array( 'core' => 'plugins', 'plugins' => 'list', 'list' => 'files', 'files' => 'db', 'db' => 'render', 'render' => 'vuln', 'vuln' => 'checks', 'checks' => 'finish' );
				$state['phase']   = isset( $order[ $phase ] ) ? $order[ $phase ] : 'finish';
				$state['offset']  = 0;
			}
		}

		$state['marker']   = '';
		$state['attempts'] = 0;
		self::save_findings();
		self::save_state( $state );
		return $state;
	}

	public static function progress( $state ) {
		if ( empty( $state ) ) {
			return array( 'pct' => 0, 'label' => 'Idle', 'done' => true );
		}
		if ( ! empty( $state['done'] ) ) {
			return array( 'pct' => 100, 'label' => 'Finished', 'done' => true );
		}
		$o = isset( $state['offset'] ) ? (int) $state['offset'] : 0;
		switch ( $state['phase'] ) {
			case 'core':
				$t = max( 1, (int) $state['core_total'] );
				return array( 'pct' => (int) ( 10 * min( 1, $o / $t ) ), 'label' => 'Verifying WordPress core files', 'done' => false );
			case 'plugins':
				$t    = max( 1, (int) $state['plugins_total'] );
				$left = count( $state['plugins_queue'] );
				return array( 'pct' => 10 + (int) ( 15 * ( $t - $left ) / $t ), 'label' => 'Verifying plugins against wordpress.org (' . ( $t - $left ) . ' of ' . $t . ')', 'done' => false );
			case 'list':
				return array( 'pct' => 26, 'label' => 'Building file list (' . number_format( (int) $state['total_files'] ) . ' files to scan so far)', 'done' => false );
			case 'files':
				$t = max( 1, (int) $state['total_files'] );
				return array( 'pct' => 30 + (int) ( 58 * min( 1, $o / $t ) ), 'label' => 'Scanning files (' . number_format( $o ) . ' of ' . number_format( $t ) . ')', 'done' => false );
			case 'db':
				return array( 'pct' => 88 + (int) $state['db_step'], 'label' => 'Scanning database', 'done' => false );
			case 'render':
				return array( 'pct' => 93, 'label' => 'Loading pages as a visitor and as Googlebot', 'done' => false );
			case 'vuln':
				$t    = max( 1, (int) $state['vuln_total'] );
				$left = is_array( $state['vuln_queue'] ) ? count( $state['vuln_queue'] ) : $t;
				return array( 'pct' => 94 + (int) ( 3 * ( $t - $left ) / $t ), 'label' => 'Checking installed versions for known vulnerabilities (' . ( $t - $left ) . ' of ' . $t . ')', 'done' => false );
			default:
				return array( 'pct' => 97, 'label' => 'Checking users, config and critical files', 'done' => false );
		}
	}

	/* ---------------------------------------------------------------------
	 * Phase: core checksums
	 * ------------------------------------------------------------------- */

	public static function core_sums() {
		$sums = get_transient( 'mcss_core_sums' );
		if ( is_array( $sums ) ) {
			return $sums;
		}
		if ( $sums === 'none' ) {
			return false;
		}
		$wp_version = '';
		include ABSPATH . WPINC . '/version.php';
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$sums = get_core_checksums( $wp_version, get_locale() );
		if ( ! is_array( $sums ) ) {
			$sums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $sums ) ) {
			set_transient( 'mcss_core_sums', 'none', 600 );
			return false;
		}
		$clean = array();
		foreach ( $sums as $file => $md5 ) {
			if ( strpos( $file, 'wp-content/' ) === 0 ) {
				continue;
			}
			$clean[ $file ] = $md5;
		}
		set_transient( 'mcss_core_sums', $clean, HOUR_IN_SECONDS );
		return $clean;
	}

	private static function append_verified( &$state, $paths ) {
		if ( empty( $paths ) ) {
			return;
		}
		update_option( 'mcss_' . $state['id'] . '_ver_' . (int) $state['verified_chunks'], $paths, false );
		$state['verified_chunks']++;
	}

	private static function load_verified( $state ) {
		$set = array();
		for ( $i = 0; $i < (int) $state['verified_chunks']; $i++ ) {
			$c = get_option( 'mcss_' . $state['id'] . '_ver_' . $i, array() );
			if ( is_array( $c ) ) {
				foreach ( $c as $p ) {
					$set[ $p ] = 1;
				}
			}
		}
		return $set;
	}

	private static function phase_core( $state, $deadline ) {
		$sums = self::core_sums();
		if ( ! $sums ) {
			$state['notes'][] = 'Could not download official core checksums (api.wordpress.org unreachable or unknown version). Core files were pattern-scanned instead.';
			$state['phase']   = 'plugins';
			$state['offset']  = 0;
			return $state;
		}
		$files               = array_keys( $sums );
		$total               = count( $files );
		$state['core_total'] = $total;
		$verified            = array();
		$i                   = (int) $state['offset'];
		$skip_mod            = array( 'readme.html' => 1, 'license.txt' => 1, 'wp-config-sample.php' => 1 );

		for ( ; $i < $total; $i++ ) {
			if ( ( $i % 50 ) === 0 && microtime( true ) >= $deadline ) {
				break;
			}
			$rel = $files[ $i ];
			$abs = self::abs( $rel );
			if ( ! is_file( $abs ) || ! is_readable( $abs ) ) {
				continue;
			}
			$md5      = @md5_file( $abs );
			$expected = $sums[ $rel ];
			if ( $md5 && ( $md5 === $expected || ( is_array( $expected ) && in_array( $md5, $expected, true ) ) ) ) {
				$verified[] = $rel;
			} elseif ( ! isset( $skip_mod[ $rel ] ) ) {
				$ext = self::ext( $rel );
				$sev = ( self::is_php_ext( $ext ) || $ext === 'js' ) ? 'high' : 'low';
				self::add( $sev, 'core_modified', 'WordPress core file does not match the official release', $rel, 0, '', 'Replace it with a clean copy of the same WordPress version.' );
			}
		}
		self::append_verified( $state, $verified );
		$state['offset'] = $i;
		if ( $i >= $total ) {
			$state['phase']  = 'plugins';
			$state['offset'] = 0;
		}
		return $state;
	}

	/* ---------------------------------------------------------------------
	 * Phase: plugin checksums (wordpress.org plugins only)
	 * ------------------------------------------------------------------- */

	private static function phase_plugins( $state, $deadline ) {
		while ( ! empty( $state['plugins_queue'] ) && microtime( true ) < $deadline ) {
			reset( $state['plugins_queue'] );
			$slug    = key( $state['plugins_queue'] );
			$version = $state['plugins_queue'][ $slug ];
			unset( $state['plugins_queue'][ $slug ] );

			$status = 'unverifiable';
			if ( $version !== '' && preg_match( '~^[a-z0-9._-]+$~i', $slug ) ) {
				$url  = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
				$resp = wp_remote_get( $url, array( 'timeout' => 8 ) );
				$code = is_wp_error( $resp ) ? 0 : (int) wp_remote_retrieve_response_code( $resp );
				if ( $code === 200 ) {
					$data = json_decode( wp_remote_retrieve_body( $resp ), true );
					if ( is_array( $data ) && ! empty( $data['files'] ) && is_array( $data['files'] ) ) {
						$status = self::verify_plugin( $state, $slug, $data['files'] );
					}
				} elseif ( $code === 404 ) {
					// No checksums for this version. If the slug itself is a wordpress.org plugin, say so: a premium plugin
					// sharing a slug looks like this, and so does a plugin whose version header was edited to dodge verification.
					$info = wp_remote_get( 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode( $slug ) . '&request[fields][sections]=0&request[fields][versions]=0', array( 'timeout' => 8 ) );
					$j    = is_wp_error( $info ) ? null : json_decode( wp_remote_retrieve_body( $info ), true );
					if ( is_array( $j ) && empty( $j['error'] ) && ! empty( $j['version'] ) ) {
						$status = 'unknown_version';
						self::add( 'low', 'plugin_unknown_version', 'Plugin slug is on wordpress.org but version ' . $version . ' is not, so its files could not be verified', rtrim( self::rel( WP_PLUGIN_DIR ), '/' ) . '/' . $slug . '/', 0, 'wordpress.org has ' . $j['version'], 'Usually a premium plugin sharing a slug. If this is meant to be the free plugin, reinstall it.', $version );
					}
				}
			}
			$state['plugins_status'][ $slug ] = $status;
		}
		if ( empty( $state['plugins_queue'] ) ) {
			$state['phase']  = 'list';
			$state['offset'] = 0;
		}
		return $state;
	}

	private static function sum_matches( $abs, $sum ) {
		if ( ! empty( $sum['sha256'] ) ) {
			$h = @hash_file( 'sha256', $abs );
			return $h && in_array( $h, (array) $sum['sha256'], true );
		}
		$h = @md5_file( $abs );
		return $h && isset( $sum['md5'] ) && in_array( $h, (array) $sum['md5'], true );
	}

	private static function verify_plugin( &$state, $slug, $files ) {
		$dir_rel  = rtrim( self::rel( WP_PLUGIN_DIR ), '/' ) . '/' . $slug . '/';
		$verified = array();
		$bad      = array();
		$checked  = 0;
		foreach ( $files as $file => $sum ) {
			$ext = self::ext( $file );
			if ( ! self::is_php_ext( $ext ) && $ext !== 'js' ) {
				continue;
			}
			$rel = $dir_rel . ltrim( self::norm( $file ), '/' );
			$abs = self::abs( $rel );
			if ( strpos( $rel, '..' ) !== false || ! is_file( $abs ) || ! is_readable( $abs ) ) {
				continue;
			}
			$checked++;
			if ( is_array( $sum ) && self::sum_matches( $abs, $sum ) ) {
				$verified[] = $rel;
			} else {
				$bad[] = $rel;
			}
		}
		if ( $checked === 0 ) {
			return 'unverifiable';
		}
		// Only when nearly everything differs is this a different product sharing the slug. Anything less is tampering.
		if ( $checked >= 5 && count( $bad ) > 0.8 * $checked ) {
			self::add( 'low', 'plugin_not_release', 'Plugin does not match the wordpress.org release with the same slug and version', $dir_rel, 0, '', 'Usually a premium or custom build sharing a slug. Its files were pattern-scanned instead.' );
			return 'differs';
		}
		foreach ( $bad as $i => $rel ) {
			$state['mismatch'][ $rel ] = 1;
			if ( $i < 60 ) {
				self::add( 'high', 'plugin_modified', 'Plugin file differs from the official wordpress.org release', $rel, 0, '', 'Reinstall the plugin from wordpress.org to restore the original file.' );
			}
		}
		if ( count( $bad ) > 60 ) {
			self::add( 'high', 'plugin_modified_many', count( $bad ) . ' files in this plugin differ from the official release (first 60 listed)', $dir_rel, 0, '', 'Delete the plugin folder and reinstall it from wordpress.org.' );
		}
		self::append_verified( $state, $verified );
		return 'verified';
	}

	/* ---------------------------------------------------------------------
	 * Phase: build file list
	 * ------------------------------------------------------------------- */

	/**
	 * Resumable depth-first walk. The directory stack lives in the scan state, so a huge uploads folder
	 * is spread over as many steps as it needs instead of one request that can time out.
	 * Cache, backup and VCS folders are still walked, but only executable and server-config files are listed from them.
	 */
	private static function phase_list( $state, $deadline ) {
		$content_rel = rtrim( self::rel( WP_CONTENT_DIR ), '/' ) . '/';
		if ( ! is_array( $state['dir_stack'] ) ) {
			$state['dir_stack'] = array( rtrim( self::base(), '/' ) );
			if ( strpos( self::norm( WP_CONTENT_DIR ) . '/', self::base() ) !== 0 ) {
				$state['dir_stack'][] = self::norm( WP_CONTENT_DIR );
			}
			update_option( 'mcss_' . $state['id'] . '_buf', array(), false );
		}

		$ctx = array(
			'verified'    => self::load_verified( $state ),
			'sums'        => self::core_sums(),
			'uploads_rel' => self::uploads_rel(),
			'plugins_rel' => rtrim( self::rel( WP_PLUGIN_DIR ), '/' ) . '/',
			'content_rel' => $content_rel,
			'own'         => self::norm( (string) realpath( __FILE__ ) ),
			'state'       => $state,
		);

		$light_names = array( 'node_modules' => 1, '.git' => 1, '.svn' => 1, '.hg' => 1 );
		$light_rel   = array();
		foreach ( array( 'cache', 'uploads/cache', 'updraft', 'ai1wm-backups', 'backups-dup-lite', 'backup-db', 'wflogs', 'litespeed', 'nitropack', 'et-cache', 'wp-rocket-config', 'mcss-quarantine', 'uploads/wp-file-manager-pro/fm_backup' ) as $d ) {
			$light_rel[ $content_rel . $d ] = 1;
		}
		$light_rel = apply_filters( 'mcss_skip_dirs', $light_rel );

		$buf = get_option( 'mcss_' . $state['id'] . '_buf', array() );
		$buf = is_array( $buf ) ? $buf : array();

		while ( ! empty( $state['dir_stack'] ) && microtime( true ) < $deadline ) {
			$item  = array_pop( $state['dir_stack'] );
			$light = strpos( $item, 'R|' ) === 0;
			$dir   = $light ? substr( $item, 2 ) : $item;
			$names = @scandir( $dir );
			if ( ! is_array( $names ) ) {
				continue;
			}
			foreach ( $names as $name ) {
				if ( $name === '.' || $name === '..' ) {
					continue;
				}
				$abs = $dir . '/' . $name;
				if ( is_dir( $abs ) ) {
					if ( is_link( $abs ) ) {
						if ( ++$state['symlinks'] <= 20 ) {
							self::add( 'low', 'symlink_dir', 'Symlinked folder was not followed', self::rel( $abs ), 0, '-> ' . self::clean_snip( (string) @readlink( $abs ) ), 'The scanner does not leave the site through symlinks. Check that you know where this one points.' );
						}
						continue;
					}
					$sub_light            = $light || isset( $light_names[ $name ] ) || isset( $light_rel[ self::rel( $abs ) ] );
					$state['dir_stack'][] = ( $sub_light ? 'R|' : '' ) . $abs;
					continue;
				}
				if ( ! is_file( $abs ) ) {
					continue;
				}
				try {
					$rel = self::list_file( $abs, $name, $light, $ctx );
				} catch ( \Throwable $e ) {
					$rel = null;
				}
				if ( $rel !== null ) {
					$buf[] = $rel;
					$state['total_files']++;
					if ( count( $buf ) >= self::CHUNK ) {
						update_option( 'mcss_' . $state['id'] . '_list_' . (int) $state['list_chunks'], $buf, false );
						$state['list_chunks']++;
						$buf = array();
					}
				}
			}
		}

		if ( empty( $state['dir_stack'] ) ) {
			if ( ! empty( $buf ) ) {
				update_option( 'mcss_' . $state['id'] . '_list_' . (int) $state['list_chunks'], $buf, false );
				$state['list_chunks']++;
			}
			delete_option( 'mcss_' . $state['id'] . '_buf' );
			if ( $state['symlinks'] > 20 ) {
				$state['notes'][] = $state['symlinks'] . ' symlinked folders were not followed. Only the first 20 are listed.';
			}
			$state['phase']  = 'files';
			$state['offset'] = 0;
		} else {
			update_option( 'mcss_' . $state['id'] . '_buf', $buf, false );
		}
		return $state;
	}

	/** Location checks for one file. Returns its relative path when its contents should be pattern-scanned, else null. */
	private static function list_file( $abs, $name, $light, $ctx ) {
		$abs = self::norm( $abs );
		if ( $abs === $ctx['own'] ) {
			return null;
		}
		$rel   = self::rel( $abs );
		$ext   = self::ext( $name );
		$php   = self::is_php_ext( $ext );
		$sums  = $ctx['sums'];
		$state = $ctx['state'];
		$conf  = ( $name === '.htaccess' || $name === '.user.ini' || $name === 'php.ini' );

		if ( $light ) {
			return ( $php || $conf || $ext === 'ico' ) ? $rel : null;
		}

		if ( $sums && ( self::under( $rel, 'wp-admin/' ) || self::under( $rel, 'wp-includes/' ) ) && ! isset( $sums[ $rel ] ) ) {
			if ( $php ) {
				self::add( 'high', 'core_unknown', 'PHP file inside a WordPress core folder that is not part of WordPress', $rel );
			} elseif ( $ext === 'js' ) {
				self::add( 'low', 'core_unknown_js', 'Script inside a WordPress core folder that is not part of WordPress', $rel );
			}
		}

		self::check_exposed( $rel, $name, $ext, (int) @filesize( $abs ), $ctx['content_rel'] );

		if ( $php && strpos( $rel, '/' ) === false && $rel !== 'wp-config.php' && ! preg_match( '~^wp-config-backup-mcss-\d{8}-\d{6}-[a-z0-9]{10}\.php$~', $rel ) ) {
			$known = $sums ? isset( $sums[ $rel ] ) : in_array( $rel, array( 'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php' ), true );
			if ( ! $known ) {
				self::add( 'medium', 'root_unknown', 'PHP file in the site root that is not part of WordPress', $rel, 0, '', 'Backup and migration tools leave files here. Confirm you know what it is.' );
			}
		}

		if ( isset( $ctx['verified'][ $rel ] ) ) {
			return null;
		}

		if ( $php && self::under( $rel, $ctx['plugins_rel'] ) ) {
			$rest = substr( $rel, strlen( $ctx['plugins_rel'] ) );
			$slug = substr( $rest, 0, (int) strpos( $rest, '/' ) );
			if ( $slug !== '' && isset( $state['plugins_status'][ $slug ] ) && $state['plugins_status'][ $slug ] === 'verified' && ! isset( $state['mismatch'][ $rel ] ) ) {
				self::add( 'medium', 'plugin_extra', 'PHP file inside a verified plugin that is not in the official release', $rel );
			}
		}

		if ( self::under( $rel, $ctx['uploads_rel'] ) ) {
			if ( preg_match( '~\.(?:php\d?|phtml?|pht|phar|pgif)\.[a-z0-9]+$~i', $name ) ) {
				self::add( 'medium', 'double_ext', 'Upload with a PHP double extension', $rel );
			}
			if ( $name === '.htaccess' ) {
				self::add( 'low', 'uploads_htaccess', 'Server config file inside the uploads folder', $rel, 0, '', 'Fine if a security plugin put it there. An attacker can also use one to switch PHP execution back on for a sub-folder, so open it and read it.' );
			}
		}

		return ( $php || $conf || $ext === 'js' || $ext === 'ico' ) ? $rel : null;
	}

	/** Files that leak secrets or data when they sit in a web-accessible folder. */
	private static function check_exposed( $rel, $name, $ext, $size, $content_rel ) {
		if ( preg_match( '~^wp-config~i', $name ) && $name !== 'wp-config.php' && $name !== 'wp-config-sample.php' && ! self::is_php_ext( $ext ) ) {
			self::add( 'high', 'exposed_config', 'Copy of wp-config.php that the web server will hand out as plain text', $rel, 0, '', 'It contains the database password and salts. Delete it, then change the database password.' );
			return;
		}
		if ( preg_match( '~^adminer(?:[-_.][\w.-]*)?\.php$|^phpmyadmin\.php$~i', $name ) ) {
			self::add( 'high', 'exposed_dbtool', 'Database admin tool left in a web-accessible folder', $rel );
			return;
		}
		if ( $name === '.env' || preg_match( '~^\.env\.~', $name ) ) {
			self::add( 'medium', 'exposed_env', 'Environment file in a web-accessible folder', $rel, 0, '', 'Usually holds credentials. Move it above the web root or block it at the server.' );
			return;
		}
		$depth = substr_count( $rel, '/' );
		$top   = $depth === 0 || ( $depth === 1 && self::under( $rel, $content_rel ) );
		if ( preg_match( '~\.sql(?:\.gz|\.zip|\.bz2)?$~i', $name ) && $size > 200000 ) {
			self::add( 'medium', 'exposed_sql', 'Database dump in a web-accessible folder (' . size_format( $size ) . ')', $rel, 0, '', 'Anyone who guesses the URL can download the whole database.' );
			return;
		}
		if ( $top && preg_match( '~\.(?:zip|tar|gz|tgz|rar|7z|wpress|bak)$~i', $name ) && $size > 5000000 ) {
			self::add( 'low', 'exposed_archive', 'Large archive in a top-level web folder (' . size_format( $size ) . ')', $rel, 0, '', 'Looks like a site backup. Download it and remove it from the server.' );
			return;
		}
		if ( $name === 'debug.log' && self::under( $rel, $content_rel ) && $depth === 1 && $size > 0 ) {
			self::add( 'low', 'exposed_debuglog', 'debug.log is publicly readable on most hosts (' . size_format( $size ) . ')', $rel, 0, '', 'It leaks paths, plugin names and sometimes data. Turn off WP_DEBUG_LOG or move the log.' );
		}
	}

	/* ---------------------------------------------------------------------
	 * Phase: pattern scan
	 * ------------------------------------------------------------------- */

	private static function list_item( $state, $offset ) {
		$ci = (int) floor( $offset / self::CHUNK );
		if ( self::$chunk_cache['i'] !== $ci ) {
			$d                 = get_option( 'mcss_' . $state['id'] . '_list_' . $ci, array() );
			self::$chunk_cache = array( 'i' => $ci, 'd' => is_array( $d ) ? $d : array() );
		}
		$k = $offset % self::CHUNK;
		return isset( self::$chunk_cache['d'][ $k ] ) ? self::$chunk_cache['d'][ $k ] : null;
	}

	private static function phase_files( $state, $deadline ) {
		$total       = (int) $state['total_files'];
		$i           = (int) $state['offset'];
		$uploads_rel = self::uploads_rel();
		$rules       = array( 'php' => self::php_rules(), 'js' => self::js_rules(), 'conf' => self::conf_rules() );

		for ( ; $i < $total; $i++ ) {
			if ( microtime( true ) >= $deadline ) {
				break;
			}
			$rel = self::list_item( $state, $i );
			if ( $rel === null ) {
				continue;
			}
			try {
				self::scan_file( $rel, $uploads_rel, $rules );
			} catch ( \Throwable $e ) {
				continue;
			}
		}
		$state['offset'] = $i;
		if ( $i >= $total ) {
			$state['phase']  = 'db';
			$state['offset'] = 0;
		}
		return $state;
	}

	/**
	 * Pattern-scan one file in 1.5 MB windows that overlap, so padding the top of a file cannot push a payload out of view.
	 * A rule the regex engine refuses to finish is reported, never silently skipped.
	 */
	private static function scan_file( $rel, $uploads_rel, $rules ) {
		$abs = self::abs( $rel );
		if ( ! is_file( $abs ) || ! is_readable( $abs ) ) {
			return;
		}
		$size = (int) @filesize( $abs );
		if ( $size === 0 ) {
			return;
		}
		$name = basename( $rel );
		$ext  = self::ext( $name );
		$php  = self::is_php_ext( $ext );
		$set  = $php ? $rules['php'] : ( $ext === 'js' ? $rules['js'] : $rules['conf'] );
		$max  = 20 * 1024 * 1024;
		$keep = 8192;

		$fh = @fopen( $abs, 'rb' );
		if ( ! $fh ) {
			return;
		}
		$seen      = array();
		$hits      = 0;
		$line_base = 0;
		$read      = 0;
		$first     = true;
		$rx_error  = false;

		while ( ! feof( $fh ) && $read < $max && $hits < 6 ) {
			$content = fread( $fh, self::MAX_READ );
			if ( ! is_string( $content ) || $content === '' ) {
				break;
			}

			if ( $ext === 'ico' ) {
				if ( preg_match( '~<\?(?:php|=|\s)~i', $content ) ) {
					self::add( 'high', 'php_in_ico', 'Icon file contains PHP code', $rel );
					break;
				}
			} else {
				if ( $first && $php && self::under( $rel, $uploads_rel ) ) {
					$silence = $size < 200 && preg_match( '~^\s*<\?php\s*(?://[^\n]*|/\*.*?\*/)?\s*(?:\?>)?\s*$~s', $content );
					if ( ! $silence ) {
						self::add( 'high', 'php_in_uploads', 'PHP file inside the uploads folder', $rel, 0, self::clean_snip( substr( $content, 0, 200 ) ), 'Uploads should only hold media. Executable code here is almost always malicious.' );
					}
				}
				foreach ( $set as $rule ) {
					if ( isset( $seen[ $rule[0] ] ) ) {
						continue;
					}
					$pos = -1;
					$ok  = true;
					foreach ( (array) $rule[3] as $n => $rx ) {
						$m = array();
						$r = @preg_match( $rx, $content, $m, PREG_OFFSET_CAPTURE );
						if ( $r === false && in_array( preg_last_error(), array( PREG_BACKTRACK_LIMIT_ERROR, PREG_RECURSION_LIMIT_ERROR, PREG_JIT_STACKLIMIT_ERROR ), true ) ) {
							$rx_error = true;
						}
						if ( $r !== 1 ) {
							$ok = false;
							break;
						}
						if ( $n === 0 ) {
							$pos = (int) $m[0][1];
						}
					}
					if ( ! $ok || ( $rule[0] === 'cyrillic_comment' && preg_match( '~/(?:languages|lang|i18n|locale|unidata)/~i', $rel ) ) ) {
						continue;
					}
					$seen[ $rule[0] ] = 1;
					$line             = $line_base + substr_count( $content, "\n", 0, $pos ) + 1;
					self::add( $rule[1], $rule[0], $rule[2], $rel, $line, self::clean_snip( substr( $content, max( 0, $pos - 40 ), 240 ) ) );
					if ( ++$hits >= 6 ) {
						break;
					}
				}
			}

			$first = false;
			$len   = strlen( $content );
			if ( $len < self::MAX_READ ) {
				break;
			}
			$line_base += substr_count( $content, "\n", 0, $len - $keep );
			$read      += $len - $keep;
			fseek( $fh, -$keep, SEEK_CUR );
		}
		fclose( $fh );

		if ( $rx_error ) {
			self::add( 'medium', 'rule_error', 'A scan rule could not finish on this file (pattern engine limit)', $rel, 0, '', 'Files are sometimes padded or malformed on purpose to cause this. Open it and read it.' );
		}
		if ( $php && $size > $max ) {
			self::add( 'medium', 'file_too_large', 'PHP file larger than 20 MB was only partly scanned (' . size_format( $size ) . ')', $rel, 0, '', 'Real PHP source is never this big. Find out what it is.' );
		}
	}

	/* ---------------------------------------------------------------------
	 * Phase: database
	 * ------------------------------------------------------------------- */

	public static function trusted_domains() {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$list = array( $host, 'google.com', 'googleapis.com', 'gstatic.com', 'googletagmanager.com', 'google-analytics.com', 'googlesyndication.com', 'doubleclick.net', 'youtube.com', 'youtube-nocookie.com', 'vimeo.com', 'facebook.net', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'licdn.com', 'tiktok.com', 'pinterest.com', 'cloudflare.com', 'cloudflareinsights.com', 'jsdelivr.net', 'unpkg.com', 'jquery.com', 'bootstrapcdn.com', 'typekit.net', 'fontawesome.com', 'hotjar.com', 'clarity.ms', 'hubspot.com', 'hs-scripts.com', 'hsforms.net', 'hs-analytics.net', 'mailchimp.com', 'list-manage.com', 'termly.io', 'cookieyes.com', 'cookiebot.com', 'stripe.com', 'paypal.com', 'paypalobjects.com', 'recaptcha.net', 'hcaptcha.com', 'calendly.com', 'typeform.com', 'wistia.com', 'wistia.net', 'soundcloud.com', 'spotify.com', 'acsbapp.com', 'userway.org', 'wp.com', 'gravatar.com', 'w.org', 'wordpress.org' );
		return apply_filters( 'mcss_trusted_script_domains', $list );
	}

	public static function is_trusted( $domain, $trusted ) {
		$domain = strtolower( $domain );
		foreach ( $trusted as $t ) {
			$t = strtolower( (string) $t );
			if ( $t === '' ) {
				continue;
			}
			if ( $domain === $t || substr( $domain, -( strlen( $t ) + 1 ) ) === '.' . $t ) {
				return true;
			}
		}
		return false;
	}

	private static function inspect_db_value( &$state, $value, $source ) {
		if ( ! is_string( $value ) || $value === '' ) {
			return;
		}
		if ( strlen( $value ) > self::MAX_READ ) {
			$value = substr( $value, 0, self::MAX_READ );
		}
		$v = str_replace( array( '\\/', '\\"', "\\'" ), array( '/', '"', "'" ), $value );
		$m = array();
		if ( preg_match_all( '~<script[^>]{0,300}?src\s*=\s*["\']?(?:https?:)?//([a-z0-9.-]+)~i', $v, $m ) ) {
			foreach ( $m[1] as $d ) {
				self::note_domain( $state, $d, $source );
			}
		}
		if ( preg_match_all( '~\.src\s*=\s*["\'](?:https?:)?//([a-z0-9.-]+)~i', $v, $m ) ) {
			foreach ( $m[1] as $d ) {
				self::note_domain( $state, $d, $source );
			}
		}
		$checks = array(
			array( 'ioc_asset_cache', 'high', 'Known malware kit indicator stored in the database', self::named( 'ioc_db' ) ),
			array( 'db_eval', 'medium', 'Obfuscated script stored in the database', self::named( 'db_eval' ) ),
		);
		foreach ( $checks as $c ) {
			$mm = array();
			if ( @preg_match( $c[3], $v, $mm, PREG_OFFSET_CAPTURE ) === 1 ) {
				self::add( $c[1], $c[0], $c[2], 'db:' . $source, 0, self::clean_snip( substr( $v, max( 0, $mm[0][1] - 40 ), 240 ) ) );
			}
		}
	}

	private static function note_domain( &$state, $domain, $source ) {
		$domain = strtolower( trim( $domain, '.' ) );
		if ( $domain === '' || strpos( $domain, '.' ) === false ) {
			return;
		}
		if ( ! isset( $state['domains'][ $domain ] ) ) {
			if ( count( $state['domains'] ) >= 200 ) {
				return;
			}
			$state['domains'][ $domain ] = array( 'n' => 0, 'where' => array() );
		}
		$state['domains'][ $domain ]['n']++;
		if ( count( $state['domains'][ $domain ]['where'] ) < 3 && ! in_array( $source, $state['domains'][ $domain ]['where'], true ) ) {
			$state['domains'][ $domain ]['where'][] = $source;
		}
	}

	/**
	 * The database is read in primary-key ranges, so no single query has to walk a whole multi-million-row table
	 * and a timeout can never restart the phase from zero.
	 */
	private static function phase_db( $state, $deadline ) {
		global $wpdb;
		$range = 20000;
		$cap   = 800;
		$plan  = array(
			0 => array( $wpdb->options, 'option_id', 'option_value', $wpdb->prepare( 'option_name NOT LIKE %s AND option_name NOT LIKE %s AND option_name NOT LIKE %s', $wpdb->esc_like( '_transient_' ) . '%', $wpdb->esc_like( '_site_transient_' ) . '%', $wpdb->esc_like( 'mcss_' ) . '%' ) ),
			1 => array( $wpdb->posts, 'ID', 'post_content', "post_status IN ('publish','private') AND post_type <> 'revision'" ),
			2 => array( $wpdb->postmeta, 'meta_id', 'meta_value', '1=1' ),
			3 => array( $wpdb->posts, 'ID', 'post_content', "post_status = 'publish' AND post_type <> 'revision'" ),
		);

		while ( (int) $state['db_step'] <= 3 && microtime( true ) < $deadline ) {
			$step = (int) $state['db_step'];
			list( $table, $id, $val, $extra ) = $plan[ $step ];

			if ( (int) $state['db_max'] < 0 ) {
				$state['db_max']  = (int) $wpdb->get_var( "SELECT MAX({$id}) FROM {$table}" );
				$state['db_cur']  = 0;
				$state['db_seen'] = 0;
			}
			if ( (int) $state['db_cur'] >= (int) $state['db_max'] || (int) $state['db_seen'] >= ( $step === 3 ? 25 : $cap ) ) {
				if ( $step !== 3 && (int) $state['db_seen'] >= $cap ) {
					$state['notes'][] = 'More than ' . $cap . ' rows in ' . $table . ' contain scripts. The first ' . $cap . ' were inspected.';
				}
				$state['db_step'] = $step + 1;
				$state['db_max']  = -1;
				continue;
			}

			$from    = (int) $state['db_cur'];
			$to      = $from + $range;
			$rules   = self::rules();
			$needles = $step === 3 ? $rules['spam'] : $rules['needles'];
			if ( empty( $needles ) ) {
				$state['db_step'] = 4;
				break;
			}
			$likes   = array();
			foreach ( $needles as $n ) {
				$likes[] = $wpdb->prepare( "{$val} LIKE %s", '%' . $wpdb->esc_like( $n ) . '%' );
			}
			$ids = $wpdb->get_col( $wpdb->prepare( "SELECT {$id} FROM {$table} WHERE {$id} > %d AND {$id} <= %d AND {$extra} AND (" . implode( ' OR ', $likes ) . ") ORDER BY {$id} ASC LIMIT 200", $from, $to ) );
			$ids = is_array( $ids ) ? $ids : array();

			foreach ( $ids as $row_id ) {
				$row_id = (int) $row_id;
				$state['db_seen']++;
				if ( $step === 0 ) {
					$row = $wpdb->get_row( $wpdb->prepare( "SELECT option_name AS n, option_value AS v FROM {$wpdb->options} WHERE option_id = %d", $row_id ) );
					if ( $row ) {
						self::inspect_db_value( $state, $row->v, 'option ' . $row->n );
					}
				} elseif ( $step === 1 ) {
					self::inspect_db_value( $state, $wpdb->get_var( $wpdb->prepare( "SELECT post_content FROM {$wpdb->posts} WHERE ID = %d", $row_id ) ), 'post ' . $row_id );
				} elseif ( $step === 2 ) {
					$row = $wpdb->get_row( $wpdb->prepare( "SELECT post_id AS p, meta_key AS k, meta_value AS v FROM {$wpdb->postmeta} WHERE meta_id = %d", $row_id ) );
					if ( $row ) {
						self::inspect_db_value( $state, $row->v, 'postmeta ' . $row->k . ' (post ' . (int) $row->p . ')' );
					}
				} else {
					$title = $wpdb->get_var( $wpdb->prepare( "SELECT post_title FROM {$wpdb->posts} WHERE ID = %d", $row_id ) );
					self::add( 'medium', 'db_spam', 'Published content contains common SEO spam keywords', 'db:post ' . $row_id, 0, self::clean_snip( (string) $title ), 'Open the post and look for injected links or hidden text.' );
				}
			}
			// A full page of hits means the range may hold more: continue right after the last one seen.
			$state['db_cur'] = ( count( $ids ) >= 200 ) ? (int) end( $ids ) : $to;
		}

		if ( (int) $state['db_step'] > 3 ) {
			$trusted = self::trusted_domains();
			foreach ( $state['domains'] as $domain => $info ) {
				$is_t                                   = self::is_trusted( $domain, $trusted );
				$state['domains'][ $domain ]['trusted'] = $is_t ? 1 : 0;
				if ( $is_t ) {
					continue;
				}
				$bad = preg_match( '~\.(?:sbs|lol|top|click|beer|icu|cfd|cyou|rest|monster|quest|bond|skin)$~i', $domain ) || preg_match( '~^\d{1,3}(?:\.\d{1,3}){3}$~', $domain );
				self::add( $bad ? 'high' : 'low', 'db_script_domain', 'External script loaded from ' . $domain, 'db:' . implode( ', ', $info['where'] ), 0, '', $bad ? 'Throwaway domain or raw IP. Treat as malicious until proven otherwise.' : 'Confirm you recognise this third-party script.', $domain );
			}
			$state['inventory']['domains'] = $state['domains'];
			$state['phase']                = 'render';
		}
		return $state;
	}

	/* ---------------------------------------------------------------------
	 * Phase: users, config, mu-plugins, baseline
	 * ------------------------------------------------------------------- */

	public static function files_in( $dir, $recursive, $cap ) {
		$out = array();
		if ( ! is_dir( $dir ) ) {
			return $out;
		}
		if ( ! $recursive ) {
			foreach ( (array) @scandir( $dir ) as $f ) {
				if ( $f === '.' || $f === '..' ) {
					continue;
				}
				$p = rtrim( self::norm( $dir ), '/' ) . '/' . $f;
				if ( is_file( $p ) ) {
					$out[] = $p;
				}
			}
			return $out;
		}
		$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::UNIX_PATHS ), \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD );
		foreach ( $it as $f ) {
			if ( $f->isFile() ) {
				$out[] = self::norm( $f->getPathname() );
				if ( count( $out ) >= 4 * $cap ) {
					break;
				}
			}
		}
		sort( $out );
		return array_slice( $out, 0, $cap );
	}

	/**
	 * Every account that can manage the site: any role carrying manage_options, direct capability grants and
	 * network super admins. Read with raw SQL so nothing hooked into the user query can hide one.
	 */
	public static function privileged_user_ids() {
		global $wpdb;
		$key   = $wpdb->get_blog_prefix() . 'capabilities';
		$likes = array( $wpdb->prepare( 'meta_value LIKE %s', '%' . $wpdb->esc_like( '"manage_options";b:1' ) . '%' ) );
		foreach ( wp_roles()->roles as $name => $role ) {
			if ( ! empty( $role['capabilities']['manage_options'] ) ) {
				$likes[] = $wpdb->prepare( 'meta_value LIKE %s', '%' . $wpdb->esc_like( '"' . $name . '"' ) . '%' );
			}
		}
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND (" . implode( ' OR ', $likes ) . ')', $key ) );
		$ids = array_map( 'intval', is_array( $ids ) ? $ids : array() );
		if ( is_multisite() ) {
			foreach ( (array) get_super_admins() as $login ) {
				$id = (int) $wpdb->get_var( $wpdb->prepare( "SELECT ID FROM {$wpdb->users} WHERE user_login = %s", $login ) );
				if ( $id ) {
					$ids[] = $id;
				}
			}
		}
		$ids = array_values( array_unique( array_filter( $ids ) ) );
		sort( $ids );
		return $ids;
	}

	private static function phase_checks( $state ) {
		$verified = self::load_verified( $state );

		/* Must-use plugins and drop-ins: inventory */
		$mu = array();
		foreach ( self::files_in( WPMU_PLUGIN_DIR, false, 500 ) as $p ) {
			if ( self::is_php_ext( self::ext( $p ) ) ) {
				$mu[] = array( 'path' => self::rel( $p ), 'size' => (int) @filesize( $p ), 'mt' => (int) @filemtime( $p ) );
			}
		}
		$dropins = array();
		foreach ( self::files_in( WP_CONTENT_DIR, false, 500 ) as $p ) {
			if ( self::is_php_ext( self::ext( $p ) ) && basename( $p ) !== 'index.php' ) {
				$dropins[] = array( 'path' => self::rel( $p ), 'size' => (int) @filesize( $p ), 'mt' => (int) @filemtime( $p ) );
			}
		}
		$state['inventory']['mu']      = $mu;
		$state['inventory']['dropins'] = $dropins;
		$state['inventory']['plugins'] = $state['plugins_status'];

		/* Administrators */
		$admins    = array();
		$bad_names = '~^(?:wp_?upd\w*|wp[-_]?support\d*|adminbackup|backup_?admin|wp[-_]?system|sysadmin\d+|deleted?_?user\d*|wordcamp\w*|wp[-_]?cron\w*|wp[-_]?update\w*)$~i';
		$bad_mail  = '~@(?:[^@]*\.)?(?:example\.(?:org|com|net)|mailinator\.com|yopmail\.com|guerrillamail\.\w+|sharklasers\.com|10minutemail\.\w+|temp-?mail\.\w+|test\.\w+)$|\.(?:test|tst|invalid|local)$~i';
		// Privileged accounts are read straight from the database. get_users() is the query malware filters to hide its admin.
		global $wpdb;
		$ids     = array_slice( self::privileged_user_ids(), 0, 300 );
		$rows    = array();
		$visible = array();
		if ( ! empty( $ids ) ) {
			$in   = implode( ',', array_map( 'intval', $ids ) );
			$rows = $wpdb->get_results( "SELECT ID, user_login, user_email, user_registered FROM {$wpdb->users} WHERE ID IN ({$in}) ORDER BY ID ASC" );
			foreach ( (array) get_users( array( 'include' => $ids, 'fields' => 'ID', 'number' => 300 ) ) as $vid ) {
				$visible[ (int) $vid ] = 1;
			}
		}
		foreach ( (array) $rows as $u ) {
			$ips      = array();
			$sessions = get_user_meta( $u->ID, 'session_tokens', true );
			if ( is_array( $sessions ) ) {
				foreach ( $sessions as $sess ) {
					if ( ! empty( $sess['ip'] ) ) {
						$ips[ $sess['ip'] ] = isset( $sess['login'] ) ? (int) $sess['login'] : 0;
					}
				}
			}
			arsort( $ips );
			$ref      = 'user:' . $u->user_login;
			$app_list = array();
			if ( class_exists( 'WP_Application_Passwords' ) ) {
				foreach ( (array) WP_Application_Passwords::get_user_application_passwords( $u->ID ) as $ap ) {
					$ap_name    = isset( $ap['name'] ) ? (string) $ap['name'] : 'unnamed';
					$app_list[] = $ap_name . ( ! empty( $ap['created'] ) ? ' (created ' . gmdate( 'Y-m-d', (int) $ap['created'] ) . ')' : '' );
					$recent     = ! empty( $ap['created'] ) && (int) $ap['created'] > time() - 30 * DAY_IN_SECONDS;
					self::add( $recent ? 'medium' : 'low', 'app_password', 'Administrator has an application password' . ( $recent ? ' created in the last 30 days' : '' ), $ref . ' / ' . $ap_name, 0, '', 'Application passwords keep working after a normal password reset. Revoke any you do not recognise.' );
				}
			}
			$admins[] = array( 'id' => (int) $u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'registered' => $u->user_registered, 'ips' => array_slice( $ips, 0, 5, true ), 'apps' => $app_list );

			if ( ! isset( $visible[ (int) $u->ID ] ) ) {
				self::add( 'high', 'hidden_admin', 'Administrator exists in the database but is hidden from the Users screen', $ref, 0, 'user ID ' . (int) $u->ID, 'Something is filtering the user list. Delete this account from the database or with WP-CLI, then find the code that hides it.' );
			}
			if ( preg_match( $bad_names, $u->user_login ) ) {
				self::add( 'high', 'user_bad_name', 'Administrator username matches names used by malware', $ref, 0, $u->user_email );
			}
			if ( preg_match( $bad_mail, (string) $u->user_email ) ) {
				self::add( 'medium', 'user_throwaway_email', 'Administrator with a placeholder or throwaway email address', $ref, 0, $u->user_email );
			}
			$reg = strtotime( $u->user_registered . ' UTC' );
			if ( $reg && $reg > time() - 30 * DAY_IN_SECONDS ) {
				self::add( 'medium', 'user_new_admin', 'Administrator account created in the last 30 days', $ref, 0, $u->user_email . ', registered ' . $u->user_registered . ' UTC', 'Confirm someone on the team created it.' );
			}
		}
		$state['inventory']['admins'] = $admins;

		/* Salts */
		$salt_vals = array();
		$undefined = 0;
		foreach ( self::salt_keys() as $k ) {
			if ( ! defined( $k ) ) {
				$undefined++;
				continue;
			}
			$v = (string) constant( $k );
			if ( stripos( $v, 'put your unique phrase here' ) !== false || $v === '' ) {
				self::add( 'high', 'salt_default', $k . ' still has the placeholder value', self::rel( self::config_path() ), 0, '', 'Login cookies on this site can be forged. Rotate the salts.' );
			} elseif ( strlen( $v ) < 32 ) {
				self::add( 'medium', 'salt_short', $k . ' is shorter than 32 characters', self::rel( self::config_path() ) );
			}
			$salt_vals[] = $v;
		}
		if ( count( $salt_vals ) !== count( array_unique( $salt_vals ) ) ) {
			self::add( 'medium', 'salt_duplicate', 'Two or more keys and salts share the same value', self::rel( self::config_path() ), 0, '', 'Rotate the salts so each one is unique.' );
		}
		if ( $undefined > 0 && $undefined < 8 ) {
			self::add( 'medium', 'salt_missing', $undefined . ' of the 8 keys and salts are not defined in wp-config.php', self::rel( self::config_path() ) );
		}

		/* Pending updates and PHP version */
		$up = get_site_transient( 'update_plugins' );
		if ( is_object( $up ) && ! empty( $up->response ) && is_array( $up->response ) ) {
			$names = array();
			foreach ( $up->response as $pfile => $info ) {
				$names[] = dirname( $pfile ) . ( isset( $info->new_version ) ? ' ' . $info->new_version : '' );
			}
			self::add( 'medium', 'updates_plugins', count( $names ) . ' plugin update(s) waiting', '', 0, implode( ', ', array_slice( $names, 0, 25 ) ), 'Outdated plugins are the most common way WordPress sites get hacked.', md5( implode( ',', $names ) ) );
		}
		$uc = get_site_transient( 'update_core' );
		if ( is_object( $uc ) && ! empty( $uc->updates[0] ) && isset( $uc->updates[0]->response ) && $uc->updates[0]->response === 'upgrade' ) {
			self::add( 'medium', 'updates_core', 'WordPress core update waiting: ' . ( isset( $uc->updates[0]->current ) ? $uc->updates[0]->current : '' ), '' );
		}
		if ( version_compare( PHP_VERSION, '8.2', '<' ) ) {
			self::add( 'low', 'php_eol', 'PHP ' . PHP_VERSION . ' no longer receives security fixes', '', 0, '', 'Switch the site to a supported PHP version in the hosting panel.' );
		}
		if ( is_dir( ABSPATH . '.git' ) ) {
			self::add( 'medium', 'exposed_git', 'A .git folder sits in the web root', '.git/', 0, '', 'Unless the server blocks it, the full source history can be downloaded.' );
		}

		if ( count( $admins ) > 8 ) {
			self::add( 'low', 'many_admins', count( $admins ) . ' administrator accounts', 'user:*', 0, '', 'Every admin is a way in. Downgrade the ones that do not need full access.' );
		}

		/* Config */
		if ( get_option( 'users_can_register' ) && in_array( get_option( 'default_role' ), array( 'administrator', 'editor' ), true ) ) {
			self::add( 'high', 'open_registration', 'Anyone can register and is given the "' . get_option( 'default_role' ) . '" role', 'db:option default_role' );
		}
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			self::add( 'low', 'file_edit_on', 'The theme and plugin file editor is enabled', '', 0, '', "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php." );
		}
		foreach ( array( 'wp-file-manager', 'wp-file-manager-pro', 'file-manager-advanced', 'filester', 'file-manager' ) as $fm ) {
			if ( is_dir( WP_PLUGIN_DIR . '/' . $fm ) ) {
				self::add( 'medium', 'file_manager', 'File manager plugin installed: ' . $fm, rtrim( self::rel( WP_PLUGIN_DIR ), '/' ) . '/' . $fm . '/', 0, '', 'Gives full file write access from wp-admin and is a frequent attack target. Remove it when not in active use.' );
			}
		}

		/* Baseline of critical files */
		$critical = array();
		$theme_rel = array();
		foreach ( self::files_in( WPMU_PLUGIN_DIR, true, 2000 ) as $p ) {
			$critical[] = $p;
		}
		foreach ( self::files_in( WP_CONTENT_DIR, false, 500 ) as $p ) {
			$critical[] = $p;
		}
		foreach ( self::files_in( ABSPATH, false, 500 ) as $p ) {
			$critical[] = $p;
		}
		if ( ! is_file( ABSPATH . 'wp-config.php' ) && is_file( dirname( ABSPATH ) . '/wp-config.php' ) ) {
			$critical[] = self::norm( dirname( ABSPATH ) . '/wp-config.php' );
		}
		foreach ( array_unique( array( get_stylesheet_directory(), get_template_directory() ) ) as $td ) {
			foreach ( self::files_in( $td, true, 3000 ) as $p ) {
				$critical[]             = $p;
				$theme_rel[ self::rel( $p ) ] = 1;
			}
		}
		$now_map = array();
		foreach ( $critical as $p ) {
			$ext  = self::ext( $p );
			$name = basename( $p );
			if ( ( ! self::is_php_ext( $ext ) && $name !== '.htaccess' && $name !== '.user.ini' ) || strpos( $name, 'wp-config-backup-mcss-' ) === 0 ) {
				continue;
			}
			$rel = self::rel( $p );
			if ( isset( $verified[ $rel ] ) ) {
				continue;
			}
			$h = @md5_file( $p );
			if ( $h ) {
				$now_map[ $rel ] = $h;
			}
		}
		$baseline = get_option( self::OPT_BASELINE, array() );
		if ( is_array( $baseline ) && ! empty( $baseline['files'] ) ) {
			$since         = wp_date( 'M j, Y H:i', (int) $baseline['time'] );
			$mu_rel        = rtrim( self::rel( WPMU_PLUGIN_DIR ), '/' ) . '/';
			$theme_changes = 0;
			foreach ( $now_map as $rel => $h ) {
				$is_new = ! isset( $baseline['files'][ $rel ] );
				if ( ! $is_new && $baseline['files'][ $rel ] === $h ) {
					continue;
				}
				if ( isset( $theme_rel[ $rel ] ) ) {
					$theme_changes++;
					if ( $theme_changes > 15 ) {
						continue;
					}
				}
				if ( $is_new ) {
					$sev = self::under( $rel, $mu_rel ) ? 'high' : 'medium';
					self::add( $sev, 'baseline_new', 'New file in a critical location since the last scan (' . $since . ')', $rel );
				} else {
					self::add( 'medium', 'baseline_changed', 'Critical file changed since the last scan (' . $since . ')', $rel );
				}
			}
			if ( $theme_changes > 15 ) {
				$state['notes'][] = $theme_changes . ' active theme files changed since the last scan. That many at once usually means a theme update.';
			}
		} else {
			$state['notes'][] = 'First scan on this site: a baseline of must-use plugins, drop-ins, root files and the active theme was recorded. Later scans report anything added or changed there.';
		}
		update_option( self::OPT_BASELINE, array( 'time' => time(), 'files' => $now_map ), false );

		$state['phase'] = 'finish';
		return $state;
	}

	/* ---------------------------------------------------------------------
	 * Finish
	 * ------------------------------------------------------------------- */

	private static function finish( $state ) {
		self::load_findings();
		$previous = get_option( self::OPT_FINDINGS, array() );
		$previous = is_array( $previous ) ? $previous : array();
		$ignored  = self::ignored();

		$counts   = array( 'high' => 0, 'medium' => 0, 'low' => 0 );
		$new_high = array();
		foreach ( self::$findings as $k => $f ) {
			if ( isset( $ignored[ $k ] ) ) {
				continue;
			}
			if ( isset( $counts[ $f['sev'] ] ) ) {
				$counts[ $f['sev'] ]++;
			}
			if ( $f['sev'] === 'high' && ! isset( $previous[ $k ] ) ) {
				$new_high[] = $f;
			}
		}
		if ( self::$dropped > 0 ) {
			$state['notes'][] = self::$dropped . ' medium or low findings were left out because a limit was reached (150 per rule, ' . self::MAX_FINDINGS . ' overall). High findings are never dropped. Fix or ignore the listed items and scan again to see the rest.';
		}

		update_option( self::OPT_FINDINGS, self::$findings, false );
		update_option(
			self::OPT_LAST,
			array(
				'finished'  => time(),
				'duration'  => time() - (int) $state['started'],
				'mode'      => $state['mode'],
				'files'     => (int) $state['total_files'],
				'counts'    => $counts,
				'inventory' => $state['inventory'],
				'notes'     => $state['notes'],
			),
			false
		);

		self::cleanup_chunks( $state );
		delete_option( self::OPT_RUN );
		self::$findings = null;
		delete_transient( 'mcss_core_sums' );

		MCSS_Log::add( 'scan_finished', $state['mode'], $counts['high'] . ' high, ' . $counts['medium'] . ' medium, ' . $counts['low'] . ' low' );
		// Every scan mode reports new high findings. Otherwise running a manual scan would be a way to absorb them quietly.
		if ( ! empty( $new_high ) && $state['mode'] !== 'cli' ) {
			$lines = array();
			foreach ( array_slice( $new_high, 0, 40 ) as $f ) {
				$lines[] = '* ' . $f['title'];
				if ( $f['path'] !== '' ) {
					$lines[] = '  ' . $f['path'] . ( $f['line'] ? ' (line ' . $f['line'] . ')' : '' );
				}
			}
			$lines[] = '';
			$lines[] = 'Review: ' . admin_url( 'tools.php?page=mcss' );
			MCSS_Alerts::send( 'scan_new_high', count( $new_high ) . ' new high severity finding(s) in the ' . $state['mode'] . ' scan', $lines, true, false );
		}
		$brief = array();
		foreach ( array_slice( $new_high, 0, 25 ) as $f ) {
			$brief[] = array( 'title' => $f['title'], 'path' => $f['path'] );
		}
		MCSS_Alerts::webhook( 'scan', array( 'mode' => $state['mode'], 'counts' => $counts, 'new_high' => $brief, 'files_scanned' => (int) $state['total_files'], 'scanner_sha256' => MCSS_Scanner::self_hash() ), true );

		$state['done']   = true;
		$state['phase']  = 'done';
		$state['db_ids'] = array();
		$state['domains'] = array();
		$state['render_sum'] = array();
		$state['render_domains'] = array();
		return $state;
	}

	/* ---------------------------------------------------------------------
	 * Cron
	 * ------------------------------------------------------------------- */

	private static function manual_running() {
		$state = self::state();
		return ! empty( $state ) && empty( $state['done'] ) && $state['mode'] !== 'cron' && ( time() - (int) $state['updated'] ) < 600;
	}

	public static function cron_start() {
		if ( self::manual_running() || ! self::lock() ) {
			return;
		}
		self::start( 'cron' );
		self::unlock();
		self::cron_continue();
	}

	public static function cron_continue() {
		$state = self::state();
		if ( empty( $state ) || ! empty( $state['done'] ) || $state['mode'] !== 'cron' ) {
			return;
		}
		// Book the next run before doing any work. If this step dies, the chain carries on and the stuck-step counter takes over.
		if ( ! wp_next_scheduled( 'mcss_continue' ) ) {
			wp_schedule_single_event( time() + 90, 'mcss_continue' );
		}
		if ( ( time() - (int) $state['started'] ) > 6 * HOUR_IN_SECONDS ) {
			wp_clear_scheduled_hook( 'mcss_continue' );
			if ( self::lock() ) {
				$state['notes'][] = 'The background scan was stopped after six hours without finishing. Results are partial.';
				$state['phase']   = 'finish';
				self::save_state( $state );
				self::step( 10 );
				self::unlock();
			}
			return;
		}
		if ( ! self::lock() ) {
			return;
		}
		$state = self::step( 15 );
		self::unlock();
		if ( ! empty( $state['done'] ) ) {
			wp_clear_scheduled_hook( 'mcss_continue' );
		}
	}

	/* ---------------------------------------------------------------------
	 * AJAX
	 * ------------------------------------------------------------------- */

	public static function guard() {
		check_ajax_referer( 'mcss', 'nonce' );
		if ( ! current_user_can( self::cap() ) ) {
			wp_send_json_error( array( 'message' => 'Not allowed.' ), 403 );
		}
	}

	public static function ajax_start() {
		self::guard();
		if ( ! self::lock() ) {
			wp_send_json_error( array( 'message' => 'A scan step is still running. Try again in a few seconds.' ) );
		}
		wp_clear_scheduled_hook( 'mcss_continue' );
		$state = self::start( 'manual' );
		self::unlock();
		wp_send_json_success( self::progress( $state ) );
	}

	public static function ajax_step() {
		self::guard();
		if ( ! self::lock() ) {
			wp_send_json_success( array( 'busy' => true ) + self::progress( self::state() ) );
		}
		$state = self::step( 6 );
		self::unlock();
		wp_send_json_success( self::progress( $state ) );
	}

	public static function ignored() {
		$i = get_option( self::OPT_IGNORED, array() );
		return is_array( $i ) ? $i : array();
	}

	public static function ajax_ignore() {
		self::guard();
		$k = isset( $_POST['k'] ) ? preg_replace( '~[^a-f0-9]~', '', (string) wp_unslash( $_POST['k'] ) ) : '';
		$f = get_option( self::OPT_FINDINGS, array() );
		// Only a finding that a scan has already reported can be ignored. Nobody can silence a file before it is planted.
		if ( strlen( $k ) !== 32 || ! is_array( $f ) || ! isset( $f[ $k ] ) ) {
			wp_send_json_error();
		}
		$i       = self::ignored();
		$i[ $k ] = time();
		update_option( self::OPT_IGNORED, $i, false );
		MCSS_Log::add( 'finding_ignored', $f[ $k ]['path'], '[' . $f[ $k ]['sev'] . '] ' . $f[ $k ]['title'] );
		if ( $f[ $k ]['sev'] === 'high' ) {
			MCSS_Alerts::webhook( 'alert', array( 'alert' => 'finding_ignored', 'subject' => 'A high severity finding was marked as ignored', 'lines' => array( $f[ $k ]['title'], $f[ $k ]['path'], 'By: ' . self::current_login() ) ), false );
		}
		wp_send_json_success();
	}

	public static function reset_ignored() {
		if ( ! current_user_can( MCSS_Scanner::cap() ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'mcss_reset_ignored' );
		delete_option( self::OPT_IGNORED );
		wp_safe_redirect( admin_url( 'tools.php?page=mcss' ) );
		exit;
	}

	/* ---------------------------------------------------------------------
	 * Incident response tools (the only code in this plugin that changes anything)
	 * ------------------------------------------------------------------- */

	public static function salt_keys() {
		return array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );
	}

	public static function config_path() {
		if ( @file_exists( ABSPATH . 'wp-config.php' ) ) {
			return self::norm( ABSPATH . 'wp-config.php' );
		}
		$up = dirname( ABSPATH );
		if ( @file_exists( $up . '/wp-config.php' ) && ! @file_exists( $up . '/wp-settings.php' ) ) {
			return self::norm( $up . '/wp-config.php' );
		}
		return '';
	}

	private static function salt_regex( $key ) {
		return '~^([ \t]*)define\s*\(\s*([\'"])' . preg_quote( $key, '~' ) . '\2\s*,\s*(?:\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*")\s*\)\s*;~m';
	}

	/**
	 * Rotate the eight keys and salts. Aborts without touching anything unless every
	 * safety check passes: all eight found exactly once as plain string defines, backup
	 * written, new file parses as valid PHP, atomic swap, read-back verified.
	 *
	 * @return array { ok: bool, message: string }
	 */
	public static function rotate_salts() {
		$keys = self::salt_keys();
		$path = self::config_path();
		if ( $path === '' ) {
			return array( 'ok' => false, 'message' => 'wp-config.php was not found. Nothing was changed.' );
		}
		$real = realpath( $path );
		if ( $real ) {
			$path = self::norm( $real ); // If wp-config.php is a symlink, work on the real file so the link survives.
		}
		$src = @file_get_contents( $path );
		if ( ! is_string( $src ) || strlen( $src ) < 50 ) {
			return array( 'ok' => false, 'message' => 'wp-config.php could not be read. Nothing was changed.' );
		}

		$missing = array();
		foreach ( $keys as $k ) {
			if ( preg_match_all( self::salt_regex( $k ), $src ) !== 1 ) {
				$missing[] = $k;
			}
		}

		if ( count( $missing ) === count( $keys ) ) {
			foreach ( $keys as $k ) {
				if ( defined( $k ) ) {
					return array( 'ok' => false, 'message' => 'The salts on this site are defined outside wp-config.php (an included file or environment variables), so they have to be rotated there. Nothing was changed.' );
				}
			}
			foreach ( array( 'auth', 'secure_auth', 'logged_in', 'nonce' ) as $scheme ) {
				delete_site_option( $scheme . '_key' );
				delete_site_option( $scheme . '_salt' );
			}
			delete_site_option( 'secret_key' );
			update_option( self::OPT_SALTS, array( 'time' => time(), 'user' => self::current_login(), 'method' => 'database' ), false );
			MCSS_Log::add( 'salts_rotated', 'database' );
			return array( 'ok' => true, 'message' => 'This site keeps its salts in the database. They were cleared and WordPress will generate new ones on the next request. Everyone is now logged out.' );
		}
		if ( ! empty( $missing ) ) {
			return array( 'ok' => false, 'message' => 'These keys are missing, duplicated or written in an unusual way in wp-config.php: ' . implode( ', ', $missing ) . '. Nothing was changed. Rotate them by hand.' );
		}
		if ( ! is_writable( $path ) ) {
			return array( 'ok' => false, 'message' => 'wp-config.php is not writable by PHP on this host. Nothing was changed. Rotate the salts over SFTP or with "wp config shuffle-salts".' );
		}

		$values = array();
		$new    = $src;
		foreach ( $keys as $k ) {
			$val          = wp_generate_password( 64, true, true );
			$val          = str_replace( array( "'", '\\' ), array( '-', '_' ), $val );
			$values[ $k ] = $val;
			$new          = preg_replace_callback(
				self::salt_regex( $k ),
				function ( $m ) use ( $k, $val ) {
					return $m[1] . "define( '" . $k . "', '" . $val . "' );";
				},
				$new,
				1
			);
			if ( ! is_string( $new ) ) {
				return array( 'ok' => false, 'message' => 'Could not build the new wp-config.php. Nothing was changed.' );
			}
		}

		foreach ( $values as $k => $val ) {
			if ( substr_count( $new, "'" . $val . "'" ) !== 1 ) {
				return array( 'ok' => false, 'message' => 'Safety check failed while building the new file. Nothing was changed.' );
			}
		}
		if ( abs( strlen( $new ) - strlen( $src ) ) > 2000 || substr_count( $new, '<?php' ) !== substr_count( $src, '<?php' ) || substr_count( $new, "\n" ) !== substr_count( $src, "\n" ) ) {
			return array( 'ok' => false, 'message' => 'Safety check failed: the new file differs from the old one more than it should. Nothing was changed.' );
		}
		try {
			token_get_all( $new, TOKEN_PARSE );
		} catch ( \Throwable $e ) {
			return array( 'ok' => false, 'message' => 'Safety check failed: the new file would not be valid PHP. Nothing was changed.' );
		}

		$dir    = dirname( $path );
		$backup = $dir . '/wp-config-backup-mcss-' . gmdate( 'Ymd-His' ) . '-' . strtolower( wp_generate_password( 10, false ) ) . '.php';
		if ( ! @copy( $path, $backup ) || @md5_file( $backup ) !== md5( $src ) ) {
			@unlink( $backup );
			return array( 'ok' => false, 'message' => 'Could not write a backup copy of wp-config.php, so the rotation was not attempted. Nothing was changed.' );
		}
		@chmod( $backup, 0600 );

		$perms   = @fileperms( $path );
		$tmp     = $path . '.mcss-' . strtolower( wp_generate_password( 8, false ) ) . '.tmp.php';
		$written = false;
		if ( @file_put_contents( $tmp, $new, LOCK_EX ) === strlen( $new ) ) {
			if ( $perms ) {
				@chmod( $tmp, $perms & 0777 );
			}
			$written = @rename( $tmp, $path );
		}
		if ( ! $written ) {
			@unlink( $tmp );
			$written = ( @file_put_contents( $path, $new, LOCK_EX ) === strlen( $new ) );
		}
		clearstatcache( true, $path );
		if ( ! $written || @file_get_contents( $path ) !== $new ) {
			@copy( $backup, $path );
			clearstatcache( true, $path );
			$restored = ( @file_get_contents( $path ) === $src );
			return array( 'ok' => false, 'message' => $restored ? 'The new file could not be written. The original wp-config.php is in place and unchanged.' : 'The write failed and the automatic restore could not be confirmed. Check wp-config.php now. A backup is at ' . basename( $backup ) . ' next to it.' );
		}
		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $path, true );
		}

		$old = glob( $dir . '/wp-config-backup-mcss-*.php' );
		if ( is_array( $old ) && count( $old ) > 2 ) {
			sort( $old );
			foreach ( array_slice( $old, 0, count( $old ) - 2 ) as $f ) {
				@unlink( $f );
			}
		}

		update_option( self::OPT_SALTS, array( 'time' => time(), 'user' => self::current_login(), 'method' => 'wp-config', 'backup' => basename( $backup ) ), false );
		MCSS_Log::add( 'salts_rotated', 'wp-config.php', 'backup ' . basename( $backup ) );
		MCSS_Alerts::watch( true );
		return array( 'ok' => true, 'message' => 'All 8 keys and salts were replaced. Every session on the site is now invalid, including yours. Backup saved as ' . basename( $backup ) . '.' );
	}

	public static function current_login() {
		if ( function_exists( 'wp_get_current_user' ) ) {
			$u = wp_get_current_user();
			if ( $u && ! empty( $u->user_login ) ) {
				return $u->user_login;
			}
		}
		return defined( 'WP_CLI' ) && WP_CLI ? 'wp-cli' : 'unknown';
	}

	/**
	 * New random password for every administrator except the one pressing the button,
	 * sessions destroyed, application passwords revoked, standard reset email sent.
	 */
	public static function reset_admin_passwords( $skip_user_id ) {
		$done   = 0;
		$failed = array();
		$apps   = 0;
		global $wpdb;
		$ids   = self::privileged_user_ids();
		$users = empty( $ids ) ? array() : $wpdb->get_results( 'SELECT ID, user_login FROM ' . $wpdb->users . ' WHERE ID IN (' . implode( ',', array_map( 'intval', $ids ) ) . ')' );
		foreach ( (array) $users as $u ) {
			if ( (int) $u->ID === (int) $skip_user_id ) {
				continue;
			}
			wp_set_password( wp_generate_password( 32, true, true ), $u->ID );
			if ( class_exists( 'WP_Session_Tokens' ) ) {
				WP_Session_Tokens::get_instance( $u->ID )->destroy_all();
			}
			if ( class_exists( 'WP_Application_Passwords' ) ) {
				$list = WP_Application_Passwords::get_user_application_passwords( $u->ID );
				if ( ! empty( $list ) ) {
					$apps += count( $list );
					WP_Application_Passwords::delete_all_application_passwords( $u->ID );
				}
			}
			$sent = function_exists( 'retrieve_password' ) ? retrieve_password( $u->user_login ) : false;
			if ( $sent === true ) {
				$done++;
			} else {
				$failed[] = $u->user_login;
			}
		}
		MCSS_Log::add( 'admins_reset', '', ( $done + count( $failed ) ) . ' accounts, ' . $apps . ' application passwords revoked' );
		$msg = ( $done + count( $failed ) ) . ' administrator password(s) replaced with random ones. ' . $done . ' reset email(s) sent.';
		if ( $apps ) {
			$msg .= ' ' . $apps . ' application password(s) revoked.';
		}
		if ( $failed ) {
			$msg .= ' The email did not send for: ' . implode( ', ', $failed ) . '. Their passwords are still reset, and they can use "Lost your password?" on the login page.';
		}
		if ( $skip_user_id ) {
			$msg .= ' Your own account was left alone. Change your password from your profile.';
		}
		return array( 'ok' => true, 'message' => $msg );
	}

	public static function guard_action() {
		self::guard();
	}

	/** Quarantine, repair and the uploads rule change files, so they honour DISALLOW_FILE_MODS like core does. */
	public static function file_mods_allowed() {
		return function_exists( 'wp_is_file_mod_allowed' ) ? wp_is_file_mod_allowed( 'mcss_file_change' ) : ! ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS );
	}

	public static function ajax_rotate_salts() {
		self::guard_action();
		$r = self::rotate_salts();
		$r['ok'] ? wp_send_json_success( $r ) : wp_send_json_error( $r );
	}

	public static function ajax_reset_admins() {
		self::guard_action();
		wp_send_json_success( self::reset_admin_passwords( get_current_user_id() ) );
	}

	public static function ajax_logout_all() {
		self::guard_action();
		if ( ! class_exists( 'WP_Session_Tokens' ) ) {
			wp_send_json_error( array( 'message' => 'Session tokens are not available on this site.' ) );
		}
		MCSS_Log::add( 'sessions_ended', 'all users' );
		WP_Session_Tokens::destroy_all_for_all_users();
		wp_send_json_success( array( 'message' => 'Every login session was ended, including yours. Passwords were not changed.' ) );
	}

	/* ---------------------------------------------------------------------
	 * Report
	 * ------------------------------------------------------------------- */

	public static function visible_findings() {
		$f = get_option( self::OPT_FINDINGS, array() );
		$f = is_array( $f ) ? $f : array();
		$i = self::ignored();
		$f = array_diff_key( $f, $i );
		$order = array( 'high' => 0, 'medium' => 1, 'low' => 2 );
		uasort(
			$f,
			function ( $a, $b ) use ( $order ) {
				$x = isset( $order[ $a['sev'] ] ) ? $order[ $a['sev'] ] : 3;
				$y = isset( $order[ $b['sev'] ] ) ? $order[ $b['sev'] ] : 3;
				if ( $x !== $y ) {
					return $x - $y;
				}
				return strcmp( $a['path'], $b['path'] );
			}
		);
		return $f;
	}

	public static function text_report() {
		$last = get_option( self::OPT_LAST, array() );
		$out  = array();
		$out[] = 'Relish Security report for ' . home_url();
		if ( ! empty( $last['finished'] ) ) {
			$out[] = 'Scan finished ' . gmdate( 'Y-m-d H:i', (int) $last['finished'] ) . ' UTC, ' . (int) $last['files'] . ' files pattern-scanned, ' . (int) $last['duration'] . 's';
		}
		$out[] = '';
		foreach ( self::visible_findings() as $f ) {
			$out[] = '[' . strtoupper( $f['sev'] ) . '] ' . $f['title'];
			if ( $f['path'] !== '' ) {
				$out[] = '    ' . $f['path'] . ( $f['line'] ? ':' . $f['line'] : '' ) . ( $f['mt'] ? '  (modified ' . gmdate( 'Y-m-d H:i', $f['mt'] ) . ' UTC)' : '' );
			}
			if ( $f['snip'] !== '' ) {
				$out[] = '    > ' . $f['snip'];
			}
			if ( $f['note'] !== '' ) {
				$out[] = '    ' . $f['note'];
			}
			$out[] = '';
		}
		if ( ! empty( $last['notes'] ) ) {
			$out[] = 'Notes:';
			foreach ( $last['notes'] as $n ) {
				$out[] = '  - ' . $n;
			}
		}
		return implode( "\n", $out );
	}

	public static function download_report() {
		if ( ! current_user_can( MCSS_Scanner::cap() ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'mcss_report' );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Content-Disposition: attachment; filename="site-scan-' . gmdate( 'Ymd-Hi' ) . '.txt"' );
		echo self::text_report(); // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	/* ---------------------------------------------------------------------
	 * Phase: rendered pages (what visitors and search engines are actually served)
	 * ------------------------------------------------------------------- */

	private static function site_host() {
		return preg_replace( '~^www\.~i', '', strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) );
	}

	private static function same_host( $host ) {
		return preg_replace( '~^www\.~i', '', strtolower( (string) $host ) ) === self::site_host();
	}

	private static function render_jobs() {
		$s    = self::settings();
		$urls = array( home_url( '/' ) => 'Home page' );
		foreach ( preg_split( '~\s+~', (string) $s['render_urls'] ) as $u ) {
			$u = trim( $u );
			if ( $u === '' ) {
				continue;
			}
			if ( $u[0] === '/' ) {
				$u = home_url( $u );
			}
			if ( self::same_host( wp_parse_url( $u, PHP_URL_HOST ) ) && (int) wp_parse_url( $u, PHP_URL_PORT ) === (int) wp_parse_url( home_url(), PHP_URL_PORT ) && count( $urls ) < 8 ) {
				$urls[ esc_url_raw( $u ) ] = (string) wp_parse_url( $u, PHP_URL_PATH );
			}
		}
		$urls[ home_url( '/mcss-missing-' . strtolower( wp_generate_password( 8, false ) ) . '/' ) ] = '404 page';

		$jobs = array();
		foreach ( $urls as $url => $label ) {
			foreach ( array( 'browser', 'bot', 'referer' ) as $variant ) {
				$jobs[] = array( 'url' => $url, 'label' => $label, 'v' => $variant );
			}
		}
		return $jobs;
	}

	private static function render_fetch( $url, $variant ) {
		$ua = $variant === 'bot'
			? 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
			: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
		$headers = array( 'Accept' => 'text/html,application/xhtml+xml' );
		if ( $variant === 'referer' ) {
			$headers['Referer'] = 'https://www.google.com/';
		}
		if ( $variant !== 'browser' ) {
			$url = add_query_arg( 'mcss_nc', wp_rand( 1000, 999999 ), $url );
		}
		$out = array( 'status' => 0, 'loc_host' => '', 'body' => '', 'error' => '' );
		for ( $hop = 0; $hop < 3; $hop++ ) {
			$resp = wp_remote_get(
				$url,
				array(
					'timeout'             => 8,
					'redirection'         => 0,
					'user-agent'          => $ua,
					'headers'             => $headers,
					'cookies'             => array(),
					'sslverify'           => apply_filters( 'https_local_ssl_verify', false ),
					'limit_response_size' => self::MAX_READ,
				)
			);
			if ( is_wp_error( $resp ) ) {
				$out['error'] = $resp->get_error_message();
				return $out;
			}
			$out['status'] = (int) wp_remote_retrieve_response_code( $resp );
			$loc           = (string) wp_remote_retrieve_header( $resp, 'location' );
			if ( $out['status'] >= 300 && $out['status'] < 400 && $loc !== '' ) {
				if ( strpos( $loc, '//' ) === 0 ) {
					$loc = 'https:' . $loc;
				} elseif ( $loc[0] === '/' ) {
					$loc = home_url( $loc );
				}
				$host = (string) wp_parse_url( $loc, PHP_URL_HOST );
				if ( $host !== '' && ! self::same_host( $host ) ) {
					$out['loc_host'] = strtolower( $host );
					return $out;
				}
				$url = $loc;
				continue;
			}
			$out['body'] = (string) wp_remote_retrieve_body( $resp );
			return $out;
		}
		return $out;
	}

	private static function render_analyze( &$state, $html, $label, $variant ) {
		$ref     = 'page:' . $label;
		$trusted = self::trusted_domains();
		$sum     = array( 'title' => '', 'links' => array(), 'spam' => array() );
		$m       = array();

		if ( preg_match( '~<title[^>]*>(.*?)</title>~is', $html, $m ) ) {
			$sum['title'] = self::clean_snip( substr( wp_strip_all_tags( $m[1] ), 0, 120 ) );
		}
		if ( preg_match( self::named( 'ioc_db' ), $html, $m, PREG_OFFSET_CAPTURE ) ) {
			self::add( 'high', 'page_ioc', 'Known malware kit is live in the page visitors receive', $ref, 0, self::clean_snip( substr( $html, max( 0, $m[0][1] - 60 ), 220 ) ) );
		}

		if ( preg_match_all( '~<script\b[^>]*\bsrc\s*=\s*["\']?([^"\'\s>]+)~i', $html, $m ) ) {
			foreach ( array_unique( $m[1] ) as $src ) {
				$src  = html_entity_decode( $src );
				$full = strpos( $src, '//' ) === 0 ? 'https:' . $src : $src;
				$host = preg_match( '~^https?://~i', $full ) ? strtolower( (string) wp_parse_url( $full, PHP_URL_HOST ) ) : '';
				if ( $host !== '' && ! self::same_host( $host ) ) {
					if ( ! isset( $state['render_domains'][ $host ] ) && count( $state['render_domains'] ) < 150 ) {
						$state['render_domains'][ $host ] = $label;
					}
					continue;
				}
				$path = (string) wp_parse_url( $full, PHP_URL_PATH );
				if ( $path !== '' && $path !== '/' && ! preg_match( '~\.m?js$~i', $path ) && ! preg_match( '~/(?:wp-content|wp-includes|wp-admin|wp-json)/~', $path ) ) {
					self::add( 'medium', 'page_script_odd', 'Script served from this site\'s own domain at a path that is not a .js file', $ref, 0, self::clean_snip( $src ), 'Malware proxies its script through the site itself so no foreign domain shows up. Confirm you know what serves this URL.', $path );
				}
			}
		}

		if ( preg_match( self::named( 'page_obf' ), $html, $m, PREG_OFFSET_CAPTURE ) ) {
			self::add( 'medium', 'page_obfuscated', 'Obfuscated inline script in the rendered page', $ref, 0, self::clean_snip( substr( $html, max( 0, $m[0][1] - 40 ), 220 ) ) );
		}
		if ( preg_match( '~<meta[^>]+http-equiv\s*=\s*["\']?refresh[^>]+url\s*=\s*["\']?(https?://[^"\'\s>]+)~i', $html, $m ) && ! self::same_host( wp_parse_url( $m[1], PHP_URL_HOST ) ) ) {
			self::add( 'high', 'page_meta_refresh', 'Page sends visitors to another site with a meta refresh', $ref, 0, self::clean_snip( $m[1] ) );
		}
		if ( preg_match_all( '~<iframe\b[^>]*>~i', $html, $m ) ) {
			foreach ( $m[0] as $tag ) {
				$sm = array();
				if ( ! preg_match( '~\bsrc\s*=\s*["\']?(?:https?:)?//([a-z0-9.-]+)~i', $tag, $sm ) || self::same_host( $sm[1] ) || self::is_trusted( $sm[1], $trusted ) ) {
					continue;
				}
				if ( preg_match( '~display\s*:\s*none|visibility\s*:\s*hidden|\b(?:width|height)\s*=\s*["\']?[01](?:px)?["\'\s>]~i', $tag ) ) {
					self::add( 'medium', 'page_hidden_iframe', 'Hidden iframe loading ' . strtolower( $sm[1] ), $ref, 0, self::clean_snip( substr( $tag, 0, 220 ) ), '', strtolower( $sm[1] ) );
				}
			}
		}
		if ( preg_match( '~style\s*=\s*["\'][^"\']*(?:left|top|text-indent)\s*:\s*-\d{3,}px[^"\']*["\'][^>]*>.{0,1500}?<a\s[^>]*href=["\']https?://([a-z0-9.-]+)~is', $html, $m ) && ! self::same_host( $m[1] ) && ! self::is_trusted( $m[1], $trusted ) ) {
			self::add( 'medium', 'page_hidden_links', 'Links positioned off-screen (hidden SEO spam pattern), pointing at ' . strtolower( $m[1] ), $ref );
		}

		if ( preg_match_all( '~<a\s[^>]*href=["\']https?://([a-z0-9.-]+)~i', $html, $m ) ) {
			foreach ( array_unique( array_map( 'strtolower', $m[1] ) ) as $h ) {
				if ( ! self::same_host( $h ) && count( $sum['links'] ) < 300 ) {
					$sum['links'][] = $h;
				}
			}
		}
		$rules_all = self::rules();
		foreach ( $rules_all['spam'] as $w ) {
			if ( stripos( $html, $w ) !== false ) {
				$sum['spam'][] = $w;
			}
		}
		return $sum;
	}

	private static function phase_render( $state, $deadline ) {
		$s = self::settings();
		if ( empty( $s['render'] ) ) {
			$state['phase'] = 'vuln';
			return $state;
		}
		if ( ! is_array( $state['render_queue'] ) ) {
			$state['render_queue'] = self::render_jobs();
		}
		while ( ! empty( $state['render_queue'] ) && microtime( true ) < $deadline ) {
			$job = array_shift( $state['render_queue'] );
			$r   = self::render_fetch( $job['url'], $job['v'] );
			$sum = array( 'status' => $r['status'], 'loc_host' => $r['loc_host'], 'error' => $r['error'], 'title' => '', 'links' => array(), 'spam' => array() );
			if ( $r['body'] !== '' ) {
				$sum = array_merge( $sum, self::render_analyze( $state, $r['body'], $job['label'], $job['v'] ) );
			}
			$state['render_sum'][ $job['label'] ][ $job['v'] ] = $sum;
			if ( $job['v'] === 'browser' && $job['label'] === 'Home page' && $r['status'] === 0 ) {
				$state['notes'][]      = 'The site could not load its own home page (' . $r['error'] . '), so the rendered page checks were skipped. Some hosts block loopback requests.';
				$state['render_queue'] = array();
				$state['render_sum']   = array();
			}
		}
		if ( ! empty( $state['render_queue'] ) ) {
			return $state;
		}

		foreach ( $state['render_sum'] as $label => $set ) {
			if ( empty( $set['browser'] ) ) {
				continue;
			}
			$b   = $set['browser'];
			$ref = 'page:' . $label;
			if ( $b['loc_host'] !== '' ) {
				self::add( 'medium', 'page_redirect_all', 'This URL redirects every visitor to ' . $b['loc_host'], $ref, 0, '', 'Fine if you set that up. If not, look in .htaccess, the Redirection plugin and the siteurl/home options.' );
			}
			if ( ! empty( $b['spam'] ) ) {
				self::add( 'medium', 'page_spam', 'Rendered page contains SEO spam keywords: ' . implode( ', ', $b['spam'] ), $ref );
			}
			foreach ( array( 'bot' => 'Googlebot', 'referer' => 'visitors arriving from Google' ) as $v => $who ) {
				if ( empty( $set[ $v ] ) ) {
					continue;
				}
				$x = $set[ $v ];
				if ( $x['loc_host'] !== '' && $x['loc_host'] !== $b['loc_host'] ) {
					self::add( 'high', 'page_cloak_redirect', 'Only ' . $who . ' get redirected to ' . $x['loc_host'], $ref, 0, '', 'Conditional redirect malware. Check .htaccess, mu-plugins and the top of index.php and wp-config.php.' );
					continue;
				}
				if ( in_array( $x['status'], array( 0, 401, 403, 406, 429, 503 ), true ) && $b['status'] >= 200 && $b['status'] < 400 ) {
					$state['notes'][] = 'The test request posing as ' . $who . ' to "' . $label . '" was blocked (HTTP ' . $x['status'] . '), most likely by a firewall, so that cloaking comparison was skipped.';
					continue;
				}
				$only_spam = array_diff( $x['spam'], $b['spam'] );
				if ( ! empty( $only_spam ) ) {
					self::add( 'high', 'page_cloak_spam', 'Spam keywords are shown only to ' . $who . ': ' . implode( ', ', $only_spam ), $ref, 0, '', 'Cloaked SEO spam. The injected content is hidden from normal visitors and from you.' );
				}
				$only_links = array_values( array_diff( $x['links'], $b['links'] ) );
				if ( count( $only_links ) >= 3 ) {
					self::add( 'medium', 'page_cloak_links', count( $only_links ) . ' outbound link domains appear only for ' . $who, $ref, 0, implode( ', ', array_slice( $only_links, 0, 12 ) ) );
				}
				if ( $x['title'] !== '' && $b['title'] !== '' && $x['title'] !== $b['title'] ) {
					self::add( 'medium', 'page_cloak_title', 'Page title is different for ' . $who, $ref, 0, '"' . $b['title'] . '" vs "' . $x['title'] . '"' );
				}
			}
		}

		$trusted = self::trusted_domains();
		foreach ( $state['render_domains'] as $domain => $label ) {
			if ( self::is_trusted( $domain, $trusted ) ) {
				continue;
			}
			$bad = preg_match( '~\.(?:sbs|lol|top|click|beer|icu|cfd|cyou|rest|monster|quest|bond|skin)$~i', $domain ) || preg_match( '~^\d{1,3}(?:\.\d{1,3}){3}$~', $domain );
			self::add( $bad ? 'high' : 'low', 'page_script_domain', 'Live page loads a script from ' . $domain, 'page:' . $label, 0, '', $bad ? 'Throwaway domain or raw IP. Treat as malicious until proven otherwise.' : 'Confirm you recognise this third-party script.', $domain );
		}
		$state['inventory']['page_domains'] = array_keys( $state['render_domains'] );
		$state['phase']                     = 'vuln';
		return $state;
	}

	/* ---------------------------------------------------------------------
	 * Phase: known vulnerabilities and abandoned plugins
	 * ------------------------------------------------------------------- */

	private static function vuln_applies( $version, $op ) {
		if ( ! is_array( $op ) ) {
			return false;
		}
		$max = isset( $op['max_version'] ) ? (string) $op['max_version'] : '';
		$min = isset( $op['min_version'] ) ? (string) $op['min_version'] : '';
		if ( $max === '' && $min === '' ) {
			return false;
		}
		$ok = true;
		if ( $max !== '' ) {
			$o  = ( isset( $op['max_operator'] ) && $op['max_operator'] === 'le' ) ? 'le' : 'lt';
			$ok = version_compare( $version, $max, $o );
		}
		if ( $ok && $min !== '' ) {
			$o  = ( isset( $op['min_operator'] ) && $op['min_operator'] === 'gt' ) ? 'gt' : 'ge';
			$ok = version_compare( $version, $min, $o );
		}
		return $ok;
	}

	private static function vuln_lookup( $type, $slug, $version, $check_wporg ) {
		$out  = array( 'ok' => false, 'vulns' => array(), 'closed' => false, 'updated' => 0, 'latest' => '' );
		$base = apply_filters( 'mcss_vuln_api', 'https://www.wpvulnerability.net' );
		$url  = $type === 'core' ? $base . '/core/' . rawurlencode( $version ) . '/' : $base . '/' . $type . '/' . rawurlencode( $slug ) . '/';
		$resp = wp_remote_get( $url, array( 'timeout' => 8, 'user-agent' => 'RelishSecurity/' . self::VERSION ) );
		if ( ! is_wp_error( $resp ) && (int) wp_remote_retrieve_response_code( $resp ) === 200 ) {
			$j = json_decode( wp_remote_retrieve_body( $resp ), true );
			if ( is_array( $j ) && isset( $j['data'] ) && is_array( $j['data'] ) ) {
				$out['ok']     = true;
				$out['closed'] = ! empty( $j['data']['closed'] ) && (string) $j['data']['closed'] !== '0';
				$list          = isset( $j['data']['vulnerability'] ) && is_array( $j['data']['vulnerability'] ) ? $j['data']['vulnerability'] : array();
				foreach ( $list as $v ) {
					$op = isset( $v['operator'] ) ? $v['operator'] : null;
					if ( $type !== 'core' && ! self::vuln_applies( $version, $op ) ) {
						continue;
					}
					$cve = '';
					if ( ! empty( $v['source'] ) && is_array( $v['source'] ) ) {
						foreach ( $v['source'] as $src ) {
							if ( isset( $src['id'] ) && strpos( (string) $src['id'], 'CVE-' ) === 0 ) {
								$cve = (string) $src['id'];
								break;
							}
						}
					}
					$out['vulns'][] = array(
						'name'    => isset( $v['name'] ) ? substr( (string) $v['name'], 0, 140 ) : 'Unnamed',
						'score'   => isset( $v['impact']['cvss']['score'] ) ? (float) $v['impact']['cvss']['score'] : 0.0,
						'unfixed' => is_array( $op ) && ! empty( $op['unfixed'] ) && (string) $op['unfixed'] !== '0',
						'cve'     => $cve,
					);
					if ( count( $out['vulns'] ) >= 40 ) {
						break;
					}
				}
			}
		}
		if ( $check_wporg && $type === 'plugin' && ! $out['closed'] ) {
			$resp = wp_remote_get( 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode( $slug ) . '&request[fields][sections]=0&request[fields][versions]=0&request[fields][screenshots]=0&request[fields][banners]=0&request[fields][icons]=0', array( 'timeout' => 8 ) );
			if ( ! is_wp_error( $resp ) ) {
				$j = json_decode( wp_remote_retrieve_body( $resp ), true );
				if ( is_array( $j ) ) {
					if ( isset( $j['error'] ) && $j['error'] === 'closed' ) {
						$out['closed'] = true;
					} elseif ( ! empty( $j['last_updated'] ) ) {
						$out['updated'] = (int) strtotime( (string) $j['last_updated'] );
						$out['latest']  = isset( $j['version'] ) ? (string) $j['version'] : '';
					}
				}
			}
		}
		return $out;
	}

	private static function phase_vuln( $state, $deadline ) {
		$s = self::settings();
		if ( empty( $s['vuln'] ) ) {
			$state['phase'] = 'checks';
			return $state;
		}
		if ( ! is_array( $state['vuln_queue'] ) ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$q    = array();
			$seen = array();
			foreach ( get_plugins() as $file => $data ) {
				$slug = dirname( $file );
				if ( $slug === '.' || $slug === '' || isset( $seen[ $slug ] ) || empty( $data['Version'] ) ) {
					continue;
				}
				$seen[ $slug ] = 1;
				$q[]           = array( 'plugin', $slug, (string) $data['Version'], isset( $data['Name'] ) ? (string) $data['Name'] : $slug );
			}
			foreach ( wp_get_themes() as $theme ) {
				if ( $theme->get( 'Version' ) ) {
					$q[] = array( 'theme', $theme->get_stylesheet(), (string) $theme->get( 'Version' ), (string) $theme->get( 'Name' ) );
				}
			}
			$wp_version = '';
			include ABSPATH . WPINC . '/version.php';
			$q[]                  = array( 'core', 'wordpress', (string) $wp_version, 'WordPress' );
			$state['vuln_queue']  = $q;
			$state['vuln_total']  = count( $q );
			$state['vuln_failed'] = 0;
		}

		$cache = get_option( 'mcss_vuln_cache', array() );
		$cache = is_array( $cache ) ? $cache : array();
		$dirty = false;

		while ( ! empty( $state['vuln_queue'] ) && microtime( true ) < $deadline ) {
			list( $type, $slug, $version, $name ) = array_shift( $state['vuln_queue'] );
			$ck = $type . '|' . $slug . '|' . $version;
			if ( isset( $cache[ $ck ] ) && $cache[ $ck ]['t'] > time() - DAY_IN_SECONDS ) {
				$r = $cache[ $ck ]['r'];
			} else {
				$on_wporg = $type === 'plugin' && isset( $state['plugins_status'][ $slug ] ) && $state['plugins_status'][ $slug ] !== 'unverifiable';
				$r        = self::vuln_lookup( $type, $slug, $version, $on_wporg );
				if ( $r['ok'] ) {
					$cache[ $ck ] = array( 't' => time(), 'r' => $r );
					$dirty        = true;
				} else {
					$state['vuln_failed']++;
				}
			}

			$path = $type === 'plugin' ? rtrim( self::rel( WP_PLUGIN_DIR ), '/' ) . '/' . $slug . '/' : ( $type === 'theme' ? rtrim( self::rel( get_theme_root() ), '/' ) . '/' . $slug . '/' : '' );
			// Freemium plugins share one slug across two products with different version lines (Amelia free is 2.x, paid is 9.x).
			// When wordpress.org says the installed free version is current, records "fixed in" a higher version belong to the other product.
			if ( ! empty( $r['vulns'] ) && ! empty( $r['latest'] ) && version_compare( $version, $r['latest'], '>=' ) ) {
				$keep  = array();
				$other = 0;
				foreach ( $r['vulns'] as $v ) {
					$fixed = array();
					if ( preg_match( '~<\s*=?\s*([0-9][0-9.]*)~', $v['name'], $fixed ) && version_compare( $fixed[1], $r['latest'], '>' ) ) {
						$other++;
						continue;
					}
					$keep[] = $v;
				}
				if ( $other > 0 ) {
					self::add( 'low', 'vuln_other_line', $name . ' ' . $version . ' is the latest free release, but ' . $other . ' vulnerability record(s) for this slug refer to versions above it (a paid edition with different numbering)', $path, 0, '', 'Check the plugin changelog to confirm the free edition received the same fixes.', $version . '|' . $other );
				}
				$r['vulns'] = $keep;
			}
			if ( ! empty( $r['vulns'] ) ) {
				$worst   = 0.0;
				$unfixed = false;
				$names   = array();
				foreach ( $r['vulns'] as $v ) {
					$worst   = max( $worst, $v['score'] );
					$unfixed = $unfixed || $v['unfixed'];
					if ( count( $names ) < 4 ) {
						$names[] = $v['name'] . ( $v['cve'] ? ' (' . $v['cve'] . ')' : '' );
					}
				}
				$sev = ( $worst >= 7.0 || $unfixed ) ? 'high' : 'medium';
				self::add( $sev, 'vuln_' . $type, $name . ' ' . $version . ' has ' . count( $r['vulns'] ) . ' known vulnerabilit' . ( count( $r['vulns'] ) === 1 ? 'y' : 'ies' ) . ( $worst > 0 ? ' (worst CVSS ' . number_format( $worst, 1 ) . ')' : '' ), $path, 0, implode( ' | ', $names ), $unfixed ? 'At least one has no fix available. Remove or replace it.' : 'Update to the latest version.', $version . '|' . count( $r['vulns'] ) );
			}
			if ( $type === 'plugin' && $r['closed'] ) {
				self::add( 'medium', 'plugin_closed', $name . ' has been closed on wordpress.org', $path, 0, '', 'Closed plugins get no more updates and are often closed for security reasons. Replace it.' );
			} elseif ( $type === 'plugin' && $r['updated'] && $r['updated'] < time() - 2 * YEAR_IN_SECONDS ) {
				self::add( 'low', 'plugin_abandoned', $name . ' has not been updated on wordpress.org since ' . gmdate( 'M Y', $r['updated'] ), $path, 0, '', 'Looks abandoned. Plan a replacement.' );
			}
		}

		if ( $dirty ) {
			if ( count( $cache ) > 400 ) {
				$cache = array_slice( $cache, -300, null, true );
			}
			update_option( 'mcss_vuln_cache', $cache, false );
		}
		if ( empty( $state['vuln_queue'] ) ) {
			if ( ! empty( $state['vuln_failed'] ) && $state['vuln_failed'] >= $state['vuln_total'] ) {
				$state['notes'][] = 'The vulnerability database (wpvulnerability.net) could not be reached, so installed versions were not checked.';
			}
			$state['phase'] = 'checks';
		}
		return $state;
	}
}

/* =========================================================================
 * Activity log
 * ======================================================================= */

final class MCSS_Log {

	const DB_VERSION = '1';

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'mcss_log';
	}

	public static function maybe_install() {
		if ( get_option( 'mcss_db_version' ) === self::DB_VERSION ) {
			return;
		}
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created datetime NOT NULL,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			user_login varchar(60) NOT NULL DEFAULT '',
			ip varchar(45) NOT NULL DEFAULT '',
			event varchar(40) NOT NULL DEFAULT '',
			object varchar(191) NOT NULL DEFAULT '',
			detail text NOT NULL,
			PRIMARY KEY  (id),
			KEY created (created),
			KEY event (event)
			) {$charset};"
		);
		update_option( 'mcss_db_version', self::DB_VERSION, true );
	}

	public static function ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? substr( preg_replace( '~[^0-9a-fA-F:.]~', '', (string) $_SERVER['REMOTE_ADDR'] ), 0, 45 ) : '';
	}

	private static function forwarded() {
		foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ) as $h ) {
			if ( ! empty( $_SERVER[ $h ] ) ) {
				return substr( preg_replace( '~[^0-9a-fA-F:., ]~', '', (string) $_SERVER[ $h ] ), 0, 90 );
			}
		}
		return '';
	}

	/** Never throws and never blocks the request it is called from. */
	public static function add( $event, $object = '', $detail = '', $login = null ) {
		try {
			global $wpdb;
			if ( empty( $wpdb ) || get_option( 'mcss_db_version' ) !== self::DB_VERSION ) {
				return;
			}
			$uid = 0;
			if ( $login === null ) {
				$login = '';
				if ( function_exists( 'wp_get_current_user' ) ) {
					$u = wp_get_current_user();
					if ( $u && $u->ID ) {
						$uid   = (int) $u->ID;
						$login = $u->user_login;
					}
				}
				if ( $login === '' && defined( 'WP_CLI' ) && WP_CLI ) {
					$login = 'wp-cli';
				} elseif ( $login === '' && function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
					$login = 'cron';
				}
			}
			$fwd = self::forwarded();
			if ( $fwd !== '' ) {
				$detail = trim( $detail . ' [forwarded-for header, unverified: ' . $fwd . ']' );
			}
			$old = $wpdb->suppress_errors( true );
			$wpdb->insert(
				self::table(),
				array(
					'created'    => gmdate( 'Y-m-d H:i:s' ),
					'user_id'    => $uid,
					'user_login' => substr( (string) $login, 0, 60 ),
					'ip'         => self::ip(),
					'event'      => substr( (string) $event, 0, 40 ),
					'object'     => substr( (string) $object, 0, 191 ),
					'detail'     => substr( (string) $detail, 0, 2000 ),
				),
				array( '%s', '%d', '%s', '%s', '%s', '%s', '%s' )
			);
			$wpdb->suppress_errors( $old );
		} catch ( \Throwable $e ) {
			return;
		}
	}

	public static function hooks() {
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ), 10, 1 );
		add_action( 'user_register', array( __CLASS__, 'on_user_register' ), 998, 1 );
		add_action( 'delete_user', array( __CLASS__, 'on_delete_user' ), 10, 1 );
		add_action( 'set_user_role', array( __CLASS__, 'on_set_role' ), 10, 3 );
		add_action( 'profile_update', array( __CLASS__, 'on_profile_update' ), 10, 2 );
		add_action( 'after_password_reset', array( __CLASS__, 'on_password_reset' ), 10, 1 );
		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin_on' ), 10, 1 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_off' ), 10, 1 );
		add_action( 'deleted_plugin', array( __CLASS__, 'on_plugin_deleted' ), 10, 2 );
		add_action( 'switch_theme', array( __CLASS__, 'on_switch_theme' ), 10, 1 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrader' ), 10, 2 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'on_app_password' ), 10, 2 );
		add_action( 'wp_ajax_edit-theme-plugin-file', array( __CLASS__, 'on_file_edit' ), 0 );
		add_action( 'updated_option', array( __CLASS__, 'on_option' ), 10, 3 );
	}

	public static function on_login( $login, $user = null ) {
		$roles = ( $user && ! empty( $user->roles ) ) ? implode( ',', (array) $user->roles ) : '';
		self::add( 'login', $login, $roles, $login );
	}

	public static function on_login_failed( $username ) {
		$n = (int) get_transient( 'mcss_failed_hour' );
		if ( $n >= 200 ) {
			return;
		}
		set_transient( 'mcss_failed_hour', $n + 1, HOUR_IN_SECONDS );
		// People type passwords into the username box by mistake. Only names that belong to a real account are stored in full.
		$username = (string) $username;
		$shown    = ( username_exists( $username ) || ( is_email( $username ) && email_exists( $username ) ) ) ? $username : substr( $username, 0, 2 ) . '*** (' . strlen( $username ) . ' characters, no such user)';
		self::add( 'login_failed', $shown, $n === 199 ? 'Hourly cap reached. Further failures this hour are not logged.' : '', '' );
	}

	public static function on_user_register( $user_id ) {
		$u = get_userdata( $user_id );
		if ( $u ) {
			self::add( 'user_created', $u->user_login, 'role: ' . implode( ',', (array) $u->roles ) . ', email: ' . $u->user_email );
		}
	}

	public static function on_delete_user( $user_id ) {
		$u = get_userdata( $user_id );
		self::add( 'user_deleted', $u ? $u->user_login : 'ID ' . (int) $user_id );
	}

	public static function on_set_role( $user_id, $role, $old_roles ) {
		$u = get_userdata( $user_id );
		self::add( 'role_changed', $u ? $u->user_login : 'ID ' . (int) $user_id, implode( ',', (array) $old_roles ) . ' -> ' . $role );
	}

	public static function on_profile_update( $user_id, $old ) {
		$u = get_userdata( $user_id );
		if ( ! $u || ! $old ) {
			return;
		}
		if ( $u->user_email !== $old->user_email ) {
			self::add( 'email_changed', $u->user_login, $old->user_email . ' -> ' . $u->user_email );
		}
		if ( $u->user_pass !== $old->user_pass ) {
			self::add( 'password_changed', $u->user_login );
		}
	}

	public static function on_password_reset( $user ) {
		self::add( 'password_reset', $user ? $user->user_login : '', '', $user ? $user->user_login : '' );
	}

	public static function on_plugin_on( $plugin ) {
		self::add( 'plugin_activated', $plugin );
	}

	public static function on_plugin_off( $plugin ) {
		self::add( 'plugin_deactivated', $plugin );
	}

	public static function on_plugin_deleted( $plugin, $deleted ) {
		if ( $deleted ) {
			self::add( 'plugin_deleted', $plugin );
		}
	}

	public static function on_switch_theme( $name ) {
		self::add( 'theme_switched', $name );
	}

	public static function on_upgrader( $upgrader, $extra ) {
		if ( ! is_array( $extra ) || empty( $extra['type'] ) ) {
			return;
		}
		$items = array();
		foreach ( array( 'plugins', 'themes' ) as $k ) {
			if ( ! empty( $extra[ $k ] ) ) {
				$items = array_merge( $items, (array) $extra[ $k ] );
			}
		}
		foreach ( array( 'plugin', 'theme' ) as $k ) {
			if ( ! empty( $extra[ $k ] ) ) {
				$items[] = $extra[ $k ];
			}
		}
		if ( empty( $items ) && ! empty( $upgrader->result['destination_name'] ) ) {
			$items[] = $upgrader->result['destination_name'];
		}
		self::add( $extra['type'] . '_' . ( isset( $extra['action'] ) ? $extra['action'] : 'update' ), implode( ', ', array_slice( array_map( 'strval', $items ), 0, 20 ) ) );
	}

	public static function on_app_password( $user_id, $item ) {
		$u = get_userdata( $user_id );
		self::add( 'app_password_created', $u ? $u->user_login : 'ID ' . (int) $user_id, isset( $item['name'] ) ? (string) $item['name'] : '' );
	}

	public static function on_file_edit() {
		$file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
		$what = ! empty( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : ( ! empty( $_POST['theme'] ) ? sanitize_text_field( wp_unslash( $_POST['theme'] ) ) : '' );
		self::add( 'file_edited', $what . ' / ' . $file, 'Built-in theme and plugin editor' );
	}

	public static function on_option( $option, $old, $new ) {
		static $watch = array( 'users_can_register' => 1, 'default_role' => 1, 'admin_email' => 1, 'siteurl' => 1, 'home' => 1 );
		if ( isset( $watch[ $option ] ) && is_scalar( $old ) && is_scalar( $new ) ) {
			self::add( 'option_changed', $option, $old . ' -> ' . $new );
		}
	}

	public static function prune() {
		global $wpdb;
		$s    = MCSS_Scanner::settings();
		$days = max( 7, (int) $s['log_days'] );
		$old  = $wpdb->suppress_errors( true );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table() . ' WHERE created < %s LIMIT 5000', gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS ) ) );
		$count = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::table() );
		if ( $count > 60000 ) {
			$wpdb->query( 'DELETE FROM ' . self::table() . ' ORDER BY id ASC LIMIT ' . (int) min( 10000, $count - 50000 ) );
		}
		$wpdb->suppress_errors( $old );
	}

	public static function query( $event, $search, $page, $per_page ) {
		global $wpdb;
		$where = array( '1=1' );
		if ( $event !== '' ) {
			$where[] = $wpdb->prepare( 'event = %s', $event );
		}
		if ( $search !== '' ) {
			$like    = '%' . $wpdb->esc_like( $search ) . '%';
			$where[] = $wpdb->prepare( '(user_login LIKE %s OR ip LIKE %s OR object LIKE %s)', $like, $like, $like );
		}
		$w     = implode( ' AND ', $where );
		$old   = $wpdb->suppress_errors( true );
		$total = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::table() . ' WHERE ' . $w );
		$rows  = $wpdb->get_results( 'SELECT * FROM ' . self::table() . ' WHERE ' . $w . ' ORDER BY id DESC LIMIT ' . (int) $per_page . ' OFFSET ' . (int) ( max( 0, $page - 1 ) * $per_page ) );
		$wpdb->suppress_errors( $old );
		return array( 'total' => $total, 'rows' => is_array( $rows ) ? $rows : array() );
	}

	public static function events() {
		global $wpdb;
		$old = $wpdb->suppress_errors( true );
		$e   = $wpdb->get_col( 'SELECT DISTINCT event FROM ' . self::table() . ' ORDER BY event ASC LIMIT 100' );
		$wpdb->suppress_errors( $old );
		return is_array( $e ) ? $e : array();
	}
}

/* =========================================================================
 * Instant alerts, file watch, webhook
 * ======================================================================= */

final class MCSS_Alerts {

	public static function hooks() {
		add_action( 'user_register', array( __CLASS__, 'on_user_register' ), 999, 1 );
		add_action( 'set_user_role', array( __CLASS__, 'on_set_role' ), 20, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'on_add_role' ), 20, 2 );
		add_action( 'granted_super_admin', array( __CLASS__, 'on_super_admin' ), 20, 1 );
		add_action( 'profile_update', array( __CLASS__, 'on_profile_update' ), 20, 2 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'on_app_password' ), 20, 2 );
		add_action( 'update_option_admin_email', array( __CLASS__, 'on_admin_email' ), 20, 2 );
		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin_on' ), 20, 1 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_off' ), 20, 1 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrader' ), 20, 2 );
		add_action( 'mcss_watch', array( __CLASS__, 'cron_watch' ) );
		add_action( 'admin_init', array( __CLASS__, 'ensure_cron' ) );
	}

	/** Keeps the schedules in line with the settings. Also repairs them after a deactivate and reactivate. */
	public static function ensure_cron() {
		$s = MCSS_Scanner::settings();
		if ( ! wp_next_scheduled( 'mcss_watch' ) ) {
			wp_schedule_event( time() + 300, 'hourly', 'mcss_watch' );
		}
		$daily = wp_next_scheduled( 'mcss_daily_scan' );
		if ( ! empty( $s['daily'] ) && ! $daily ) {
			wp_schedule_event( time() + 600, 'daily', 'mcss_daily_scan' );
		} elseif ( empty( $s['daily'] ) && $daily ) {
			wp_clear_scheduled_hook( 'mcss_daily_scan' );
		}
	}

	private static function actor() {
		$who = MCSS_Scanner::current_login();
		$ip  = MCSS_Log::ip();
		return 'Done by: ' . $who . ( $ip !== '' ? ' from ' . $ip : '' );
	}

	/**
	 * Email + webhook + log. Returns true when something was actually delivered.
	 * Routine alerts stop at 12 an hour. Critical ones (accounts, tampering, critical files) have their own, higher
	 * allowance, so nobody can burn the quota with plugin toggles and then act unseen.
	 *
	 * @param bool   $critical     Use the critical allowance.
	 * @param bool   $with_webhook Also post to the webhook (scan results post their own payload).
	 * @param string $also         Extra recipient, used when the alert address itself is being changed.
	 */
	public static function send( $event, $subject, $lines, $critical = false, $with_webhook = true, $also = '' ) {
		try {
			$subject = trim( preg_replace( '~[\r\n\t]+~', ' ', (string) $subject ) );
			MCSS_Log::add( 'alert', $event, $subject );
			$key = $critical ? 'mcss_alerts_hour_c' : 'mcss_alerts_hour';
			$max = $critical ? 60 : 12;
			$n   = (int) get_transient( $key );
			if ( $n >= $max ) {
				return false;
			}
			set_transient( $key, $n + 1, HOUR_IN_SECONDS );
			if ( $n === $max - 1 ) {
				$lines[] = '';
				$lines[] = 'Alert limit reached for this kind of alert. No more of them will be emailed for the next hour. The activity log has everything.';
			}
			$s    = MCSS_Scanner::settings();
			$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
			$sent = false;
			$to   = array();
			foreach ( array( $s['email'], $also ) as $addr ) {
				if ( ! empty( $addr ) && is_email( $addr ) ) {
					$to[ strtolower( $addr ) ] = $addr;
				}
			}
			if ( ! empty( $to ) ) {
				$body = array_merge( array( $subject, '' ), $lines, array( '', 'Site: ' . home_url(), 'Time: ' . gmdate( 'Y-m-d H:i' ) . ' UTC', 'Activity log: ' . admin_url( 'tools.php?page=mcss&tab=activity' ) ) );
				$sent = (bool) wp_mail( array_values( $to ), '[' . $host . '] Relish Security alert: ' . $subject, implode( "\n", $body ) );
			}
			if ( $with_webhook && self::webhook( 'alert', array( 'alert' => $event, 'subject' => $subject, 'lines' => $lines ), $critical ) ) {
				$sent = true;
			}
			return $sent;
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/** @return bool True when a webhook is configured and the request was handed off. */
	public static function webhook( $event, $data, $blocking, $settings = null ) {
		try {
			$s = is_array( $settings ) ? $settings : MCSS_Scanner::settings();
			if ( empty( $s['webhook'] ) || ! preg_match( '~^https://~i', $s['webhook'] ) ) {
				return false;
			}
			$wp_version = '';
			include ABSPATH . WPINC . '/version.php';
			$payload = array(
				'site'    => home_url(),
				'event'   => $event,
				'time'    => gmdate( 'c' ),
				'scanner' => MCSS_Scanner::VERSION,
				'wp'      => $wp_version,
				'php'     => PHP_VERSION,
				'data'    => $data,
			);
			$host = strtolower( (string) wp_parse_url( $s['webhook'], PHP_URL_HOST ) );
			$chat = ( $host === 'hooks.slack.com' || $host === 'discord.com' || substr( $host, -12 ) === '.discord.com' );
			if ( $chat ) {
				$text = '[' . wp_parse_url( home_url(), PHP_URL_HOST ) . '] ';
				if ( $event === 'scan' ) {
					$text .= 'Scan finished: ' . $data['counts']['high'] . ' high, ' . $data['counts']['medium'] . ' medium, ' . $data['counts']['low'] . ' low. ' . count( $data['new_high'] ) . ' new high.';
					foreach ( array_slice( $data['new_high'], 0, 8 ) as $f ) {
						$text .= "\n- " . $f['title'] . ( $f['path'] !== '' ? ' (' . $f['path'] . ')' : '' );
					}
				} elseif ( $event === 'alert' ) {
					$text .= $data['subject'] . "\n" . implode( "\n", array_filter( $data['lines'] ) );
				} else {
					return false;
				}
				// File names, usernames and the like are attacker-controlled: no mentions, no disguised links.
				$text = str_replace( array( '&', '<', '>', '@' ), array( '&amp;', '&lt;', '&gt;', '@ ' ), $text );
				$payload = $host === 'hooks.slack.com' ? array( 'text' => substr( $text, 0, 3500 ) ) : array( 'content' => substr( $text, 0, 1900 ), 'allowed_mentions' => array( 'parse' => array() ) );
			}
			$body    = wp_json_encode( $payload );
			$headers = array( 'Content-Type' => 'application/json' );
			if ( ! empty( $s['secret'] ) ) {
				$headers['X-MCSS-Signature'] = 'sha256=' . hash_hmac( 'sha256', $body, $s['secret'] );
			}
			$r = wp_safe_remote_post( $s['webhook'], array( 'timeout' => $blocking ? 8 : 3, 'blocking' => (bool) $blocking, 'headers' => $headers, 'body' => $body, 'user-agent' => 'RelishSecurity/' . MCSS_Scanner::VERSION ) );
			return ! is_wp_error( $r );
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/** The scanner being switched off is the alert that matters most, so it is sent before the plugin unloads. */
	public static function on_self_deactivated() {
		self::send( 'scanner_deactivated', 'Relish Security was deactivated', array( self::actor(), '', 'Scans, alerts and the file watch have stopped on this site. If this was not you, someone with an administrator login is covering their tracks.' ), true );
	}

	/* ---- account events ---- */

	private static function admins_on() {
		$s = MCSS_Scanner::settings();
		return ! empty( $s['alert_admins'] );
	}

	/** One alert per account per request, however many role hooks fire. Sent at shutdown. */
	private static $pending = array();

	private static function queue_admin( $user_id, $rank, $event, $subject, $lines ) {
		$user_id = (int) $user_id;
		if ( empty( self::$pending ) ) {
			add_action( 'shutdown', array( __CLASS__, 'flush_admin' ), 5 );
		}
		if ( ! isset( self::$pending[ $user_id ] ) || self::$pending[ $user_id ][0] < $rank ) {
			self::$pending[ $user_id ] = array( $rank, $event, $subject, $lines );
		}
	}

	public static function flush_admin() {
		$queue         = self::$pending;
		self::$pending = array();
		foreach ( $queue as $item ) {
			self::send( $item[1], $item[2], $item[3], true );
		}
	}

	public static function on_user_register( $user_id ) {
		$u = get_userdata( $user_id );
		if ( $u && self::admins_on() && in_array( 'administrator', (array) $u->roles, true ) ) {
			self::queue_admin( $user_id, 3, 'admin_created', 'New administrator account: ' . $u->user_login, array( 'Email: ' . $u->user_email, self::actor(), '', 'If nobody on your team did this, treat the site as compromised: delete the account, rotate salts and reset admin passwords.' ) );
		}
	}

	public static function on_set_role( $user_id, $role, $old_roles ) {
		if ( $role !== 'administrator' || in_array( 'administrator', (array) $old_roles, true ) || ! self::admins_on() ) {
			return;
		}
		$u = get_userdata( $user_id );
		self::queue_admin( $user_id, 2, 'admin_promoted', 'User promoted to administrator: ' . ( $u ? $u->user_login : 'ID ' . (int) $user_id ), array( 'Previous role: ' . ( $old_roles ? implode( ',', (array) $old_roles ) : 'none' ), self::actor() ) );
	}

	public static function on_add_role( $user_id, $role ) {
		if ( $role === 'administrator' && self::admins_on() ) {
			$u = get_userdata( $user_id );
			self::queue_admin( $user_id, 1, 'admin_promoted', 'Administrator role added to: ' . ( $u ? $u->user_login : 'ID ' . (int) $user_id ), array( self::actor() ) );
		}
	}

	public static function on_super_admin( $user_id ) {
		if ( self::admins_on() ) {
			$u = get_userdata( $user_id );
			self::send( 'super_admin', 'Network super admin granted to: ' . ( $u ? $u->user_login : 'ID ' . (int) $user_id ), array( self::actor() ), true );
		}
	}

	public static function on_profile_update( $user_id, $old ) {
		$u = get_userdata( $user_id );
		if ( $u && $old && self::admins_on() && $u->user_email !== $old->user_email && in_array( 'administrator', (array) $u->roles, true ) ) {
			self::send( 'admin_email_changed', 'Email address changed on administrator ' . $u->user_login, array( $old->user_email . ' -> ' . $u->user_email, self::actor(), '', 'Changing the email is the first step of taking over an account through password reset.' ), true, true, $old->user_email );
		}
	}

	public static function on_app_password( $user_id, $item ) {
		$u = get_userdata( $user_id );
		if ( $u && self::admins_on() && in_array( 'administrator', (array) $u->roles, true ) ) {
			self::send( 'app_password', 'Application password created for administrator ' . $u->user_login, array( 'Name: ' . ( isset( $item['name'] ) ? $item['name'] : '' ), self::actor(), '', 'Application passwords give API access and keep working after a password reset.' ), true );
		}
	}

	public static function on_admin_email( $old, $new ) {
		if ( self::admins_on() && $old !== $new ) {
			self::send( 'site_email_changed', 'Site admin email changed', array( $old . ' -> ' . $new, self::actor() ), true, true, (string) $old );
		}
	}

	/* ---- plugin events ---- */

	private static function plugins_on() {
		$s = MCSS_Scanner::settings();
		return ! empty( $s['alert_plugins'] );
	}

	public static function on_plugin_on( $plugin ) {
		if ( self::plugins_on() && $plugin !== plugin_basename( MCSS_FILE ) ) {
			self::send( 'plugin_activated', 'Plugin activated: ' . $plugin, array( self::actor() ) );
		}
	}

	public static function on_plugin_off( $plugin ) {
		if ( $plugin === plugin_basename( MCSS_FILE ) ) {
			self::on_self_deactivated();
			return;
		}
		if ( self::plugins_on() ) {
			self::send( 'plugin_deactivated', 'Plugin deactivated: ' . $plugin, array( self::actor(), '', 'Attackers switch off security plugins first. Ignore this if it was you.' ) );
		}
	}

	public static function on_upgrader( $upgrader, $extra ) {
		if ( self::plugins_on() && is_array( $extra ) && isset( $extra['action'], $extra['type'] ) && $extra['action'] === 'install' && in_array( $extra['type'], array( 'plugin', 'theme' ), true ) ) {
			$name = ! empty( $upgrader->result['destination_name'] ) ? $upgrader->result['destination_name'] : 'unknown';
			self::send( $extra['type'] . '_installed', ucfirst( $extra['type'] ) . ' installed: ' . $name, array( self::actor() ) );
		}
	}

	/* ---- hourly file watch ---- */

	public static function watch_map() {
		$files = array();
		foreach ( MCSS_Scanner::files_in( WPMU_PLUGIN_DIR, true, 5000 ) as $p ) {
			$files[] = $p;
		}
		foreach ( MCSS_Scanner::files_in( WP_CONTENT_DIR, false, 500 ) as $p ) {
			$files[] = $p;
		}
		foreach ( MCSS_Scanner::files_in( ABSPATH, false, 500 ) as $p ) {
			$files[] = $p;
		}
		$cfg = MCSS_Scanner::config_path();
		if ( $cfg !== '' ) {
			$files[] = $cfg;
		}
		// The scanner watches itself and the active theme's entry point too.
		$files[] = MCSS_Scanner::norm( MCSS_FILE );
		$files[] = MCSS_Scanner::norm( MCSS_Scanner::rules_file() );
		foreach ( array_unique( array( get_stylesheet_directory(), get_template_directory() ) ) as $td ) {
			if ( is_file( $td . '/functions.php' ) ) {
				$files[] = MCSS_Scanner::norm( $td . '/functions.php' );
			}
		}
		$keep = array();
		foreach ( array_unique( $files ) as $p ) {
			$name = basename( $p );
			if ( strpos( $name, 'wp-config-backup-mcss-' ) === 0 || substr( $name, -8 ) === '.tmp.php' ) {
				continue;
			}
			if ( MCSS_Scanner::is_php_ext( MCSS_Scanner::ext( $p ) ) || $name === '.htaccess' || $name === '.user.ini' || $p === MCSS_Scanner::norm( MCSS_Scanner::rules_file() ) ) {
				$keep[] = $p;
			}
		}
		sort( $keep ); // Stable order, so a cap can never produce phantom "new" and "removed" entries.
		$keep = array_slice( $keep, 0, 3000 );
		$map  = array();
		foreach ( $keep as $p ) {
			$map[ MCSS_Scanner::rel( $p ) ] = (string) @md5_file( $p );
		}
		return $map;
	}

	/** @param bool $silent Re-baseline without alerting (used after the plugin itself changes a watched file). */
	public static function watch( $silent = false ) {
		try {
			$now  = self::watch_map();
			$prev = get_option( 'mcss_watch', array() );
			$s    = MCSS_Scanner::settings();
			if ( $silent || ! is_array( $prev ) || empty( $prev['files'] ) || empty( $s['alert_files'] ) ) {
				update_option( 'mcss_watch', array( 'time' => time(), 'files' => $now ), false );
				return;
			}
			$lines = array();
			foreach ( $now as $rel => $sig ) {
				if ( ! isset( $prev['files'][ $rel ] ) ) {
					$lines[] = 'NEW      ' . $rel;
				} elseif ( $prev['files'][ $rel ] !== $sig ) {
					$lines[] = 'CHANGED  ' . $rel;
				}
			}
			foreach ( $prev['files'] as $rel => $sig ) {
				if ( ! isset( $now[ $rel ] ) ) {
					$lines[] = 'REMOVED  ' . $rel;
				}
			}
			if ( empty( $lines ) ) {
				update_option( 'mcss_watch', array( 'time' => time(), 'files' => $now ), false );
				return;
			}
			$total = count( $lines );
			$lines = array_slice( $lines, 0, 40 );
			array_unshift( $lines, 'Since ' . gmdate( 'Y-m-d H:i', (int) $prev['time'] ) . ' UTC, in must-use plugins, drop-ins, the site root, wp-config.php, the active theme or the scanner itself:', '' );
			$lines[] = '';
			$lines[] = 'Hosts update their own must-use plugins now and then, and WordPress and theme updates change these files too. Anything else here deserves a look right away.';
			// The baseline only moves on once the alert has gone out. A change that could not be reported is reported again next hour.
			$tries = isset( $prev['tries'] ) ? (int) $prev['tries'] : 0;
			if ( self::send( 'files_changed', $total . ' critical file change(s) detected', $lines, true ) || $tries >= 24 ) {
				update_option( 'mcss_watch', array( 'time' => time(), 'files' => $now ), false );
			} else {
				$prev['tries'] = $tries + 1;
				update_option( 'mcss_watch', $prev, false );
			}
		} catch ( \Throwable $e ) {
			return;
		}
	}

	public static function cron_watch() {
		self::watch( false );
		$last = (int) get_option( 'mcss_heartbeat', 0 );
		if ( $last < time() - DAY_IN_SECONDS + 600 ) {
			update_option( 'mcss_heartbeat', time(), false );
			$l = get_option( MCSS_Scanner::OPT_LAST, array() );
			self::webhook( 'heartbeat', array( 'last_scan' => ! empty( $l['finished'] ) ? gmdate( 'c', (int) $l['finished'] ) : null, 'counts' => isset( $l['counts'] ) ? $l['counts'] : null, 'scanner_sha256' => MCSS_Scanner::self_hash() ), false );
			MCSS_Log::prune();
		}
		MCSS_Update::maybe_update_rules();
	}
}

/* =========================================================================
 * Repair and quarantine
 * ======================================================================= */

final class MCSS_Repair {

	const OPT = 'mcss_quarantine';

	public static function dir() {
		return MCSS_Scanner::norm( WP_CONTENT_DIR ) . '/mcss-quarantine';
	}

	private static function ensure_dir() {
		$d = self::dir();
		if ( ! is_dir( $d ) && ! wp_mkdir_p( $d ) ) {
			return false;
		}
		if ( ! file_exists( $d . '/.htaccess' ) ) {
			@file_put_contents( $d . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n" );
		}
		if ( ! file_exists( $d . '/index.php' ) ) {
			@file_put_contents( $d . '/index.php', "<?php\n// Silence is golden.\n" );
		}
		return is_writable( $d );
	}

	public static function items() {
		$i = get_option( self::OPT, array() );
		return is_array( $i ) ? $i : array();
	}

	/**
	 * Make PHP forget compiled copies of files that were just moved. With opcache.revalidate_freq (2s on most hosts,
	 * longer on managed ones) a request straight after a move can still run the old code and a health check would pass
	 * on a site that is really broken. Invalidate what we can, then wait out the revalidation window.
	 */
	private static function forget_compiled( $paths ) {
		$files = array();
		foreach ( (array) $paths as $p ) {
			if ( is_dir( $p ) ) {
				try {
					$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $p, \FilesystemIterator::SKIP_DOTS ) );
					foreach ( $it as $x ) {
						if ( $x->isFile() && MCSS_Scanner::is_php_ext( MCSS_Scanner::ext( $x->getFilename() ) ) ) {
							$files[] = $x->getPathname();
						}
					}
				} catch ( \Throwable $e ) {
					continue;
				}
			} else {
				$files[] = $p;
			}
		}
		if ( function_exists( 'opcache_invalidate' ) ) {
			foreach ( array_slice( $files, 0, 5000 ) as $f ) {
				@opcache_invalidate( $f, true );
			}
		}
		if ( function_exists( 'opcache_get_status' ) && @opcache_get_status( false ) ) {
			$freq = (int) ini_get( 'opcache.revalidate_freq' );
			if ( ini_get( 'opcache.validate_timestamps' ) !== '0' ) {
				sleep( min( 6, $freq + 1 ) );
			}
		}
	}

	/** HTTP status of the home page, bypassing caches. 0 when the request itself failed. */
	public static function health() {
		$r = wp_remote_get(
			add_query_arg( 'mcss_health', wp_rand( 1000, 999999 ), home_url( '/' ) ),
			array( 'timeout' => 10, 'redirection' => 3, 'sslverify' => apply_filters( 'https_local_ssl_verify', false ), 'cookies' => array(), 'headers' => array( 'Cache-Control' => 'no-cache' ) )
		);
		if ( is_wp_error( $r ) ) {
			return 0;
		}
		$code = (int) wp_remote_retrieve_response_code( $r );
		if ( $code < 500 && stripos( (string) wp_remote_retrieve_body( $r ), 'There has been a critical error on this website' ) !== false ) {
			return 500;
		}
		return $code;
	}

	private static function broke( $before, $after ) {
		return $before >= 200 && $before < 400 && ( $after === 0 || $after >= 500 );
	}

	private static function finding( $key ) {
		$f = get_option( MCSS_Scanner::OPT_FINDINGS, array() );
		return ( is_array( $f ) && isset( $f[ $key ] ) ) ? $f[ $key ] : null;
	}

	private static function resolve_finding( $key ) {
		$f = get_option( MCSS_Scanner::OPT_FINDINGS, array() );
		if ( is_array( $f ) && isset( $f[ $key ] ) ) {
			unset( $f[ $key ] );
			update_option( MCSS_Scanner::OPT_FINDINGS, $f, false );
		}
	}

	private static function inactive_component( $rel ) {
		if ( is_multisite() ) {
			return false; // Inactive here can still be active on another site in the network.
		}
		$plugins_rel = rtrim( MCSS_Scanner::rel( WP_PLUGIN_DIR ), '/' ) . '/';
		$themes_rel  = rtrim( MCSS_Scanner::rel( get_theme_root() ), '/' ) . '/';
		if ( MCSS_Scanner::under( $rel, $plugins_rel ) ) {
			$rest = substr( $rel, strlen( $plugins_rel ) );
			if ( strpos( $rest, '/' ) === false ) {
				return false;
			}
			$slug = substr( $rest, 0, strpos( $rest, '/' ) );
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			foreach ( array_keys( get_plugins() ) as $file ) {
				if ( dirname( $file ) === $slug && ( is_plugin_active( $file ) || is_plugin_active_for_network( $file ) ) ) {
					return false;
				}
			}
			return true;
		}
		if ( MCSS_Scanner::under( $rel, $themes_rel ) ) {
			$rest = substr( $rel, strlen( $themes_rel ) );
			$slug = substr( $rest, 0, (int) strpos( $rest, '/' ) );
			return $slug !== '' && $slug !== get_stylesheet() && $slug !== get_template();
		}
		return false;
	}

	/** What the UI may offer for a finding: 'repair', 'quarantine' or ''. */
	/**
	 * What can be done about a finding, in the order it is shown. Each entry is a button (kind + confirm text) or a
	 * link (href). A fix is only offered when it is reversible or verified: nothing here deletes anything for good.
	 */
	public static function actions_for( $f ) {
		$out  = array();
		$rule = $f['rule'];
		$path = $f['path'];
		$btn  = function ( $kind, $label, $confirm ) use ( $f ) {
			return array( 'kind' => $kind, 'label' => $label, 'confirm' => $confirm, 'k' => $f['k'] );
		};
		$link = function ( $label, $href ) {
			return array( 'href' => $href, 'label' => $label );
		};
		$q_confirm = 'Move this file out of the site into quarantine? The site is checked straight after and the file is put back automatically if anything breaks.';

		switch ( $rule ) {
			case 'core_modified':
			case 'plugin_modified':
				$out[] = $btn( 'repair', 'Repair', 'Download the official copy of this file, verify its checksum and swap it in? The current copy is kept in quarantine.' );
				break;
			case 'plugin_modified_many':
			case 'plugin_not_release':
			case 'plugin_closed':
			case 'plugin_abandoned':
			case 'vuln_plugin':
			case 'file_manager':
			case 'plugin_unknown_version':
				$slug = self::plugin_slug_from_path( $path );
				if ( $slug !== '' ) {
					if ( in_array( $rule, array( 'vuln_plugin', 'plugin_modified_many' ), true ) && self::plugin_update_available( $slug ) ) {
						$out[] = $btn( 'update_plugin', 'Update plugin', 'Update this plugin to the latest release from wordpress.org now? The site is checked afterwards.' );
					}
					$out[] = $btn( 'remove_plugin', 'Deactivate and quarantine', 'Deactivate this plugin and move its whole folder into quarantine? The site is checked straight after and the plugin is put back and reactivated automatically if anything breaks. You can also restore it from the Response tab.' );
				}
				break;
			case 'vuln_theme':
				$out[] = $link( 'Open themes', admin_url( 'themes.php' ) );
				break;
			case 'vuln_core':
			case 'updates_core':
				$out[] = $link( 'Open updates', admin_url( 'update-core.php' ) );
				break;
			case 'updates_plugins':
				$out[] = $btn( 'update_all_plugins', 'Update all', 'Update every plugin that has an update waiting? Plugins are updated one at a time, the site is checked after each one, and the run stops if the site stops responding.' );
				$out[] = $link( 'Open updates', admin_url( 'update-core.php' ) );
				break;
			case 'user_bad_name':
			case 'hidden_admin':
			case 'user_throwaway_email':
			case 'user_new_admin':
				$out[] = $btn( 'demote_user', 'Remove admin rights', 'Change this account to Subscriber, end its sessions and revoke its application passwords? The account and its content are kept, so this is reversible from the Users screen.' );
				$out[] = $link( 'Open user', admin_url( 'users.php?s=' . rawurlencode( substr( $path, 5 ) ) ) );
				break;
			case 'app_password':
				$out[] = $btn( 'revoke_app_password', 'Revoke', 'Revoke this application password? Whatever was using it will stop being able to log in through the API.' );
				break;
			case 'many_admins':
				$out[] = $link( 'Open administrators', admin_url( 'users.php?role=administrator' ) );
				break;
			case 'open_registration':
				$out[] = $btn( 'close_registration', 'Fix', 'Turn off open registration and set the default role to Subscriber?' );
				break;
			case 'file_edit_on':
				$out[] = $btn( 'harden_file_edit', 'Turn off editor', 'Turn off the built-in theme and plugin file editor? This is the Hardening switch and can be turned back on there.' );
				break;
			case 'salt_default':
			case 'salt_short':
			case 'salt_duplicate':
			case 'salt_missing':
				$out[] = $btn( 'rotate_salts', 'Rotate salts', 'Replace all 8 keys and salts in wp-config.php? Every user is logged out immediately, including you.' );
				break;
			case 'exposed_debuglog':
				$out[] = $btn( 'clear_debug_log', 'Empty the log', 'Empty debug.log? The current contents are kept in quarantine first so nothing is lost.' );
				break;
			case 'baseline_new':
			case 'baseline_changed':
				if ( self::can_quarantine( $path, $rule ) === true ) {
					$out[] = $btn( 'quarantine', 'Quarantine', $q_confirm );
				}
				$out[] = $btn( 'accept_baseline', 'Accept as expected', 'Record this file as expected so it is not reported again unless it changes? Only do this if you know what changed it.' );
				break;
			case 'db_spam':
			case 'db_script_domain':
			case 'db_eval':
			case 'ioc_asset_cache':
				$m = array();
				if ( in_array( $rule, array( 'db_eval', 'ioc_asset_cache' ), true ) && preg_match( '~^db:option (.+)$~', $path, $m ) && self::option_deletable( $m[1] ) ) {
					$out[] = $btn( 'trace_option', 'Find the code that reads it', 'Search every PHP file on the site for code that reads this option? Nothing is changed. Matches are added to the findings list with their own Quarantine buttons.' );
					$out[] = $btn( 'delete_option', 'Delete option', 'Delete this option from the database? Its name and value are kept in quarantine so it can be put back.' );
				}
				if ( preg_match( '~^db:post (\d+)~', $path, $m ) || preg_match( '~^db:postmeta [^(]+\(post (\d+)\)~', $path, $m ) ) {
					$out[] = $link( 'Edit post', admin_url( 'post.php?action=edit&post=' . (int) $m[1] ) );
				}
				break;
		}

		if ( empty( $out ) && $path !== '' && strpos( $path, ':' ) === false && substr( $path, -1 ) !== '/' && self::can_quarantine( $path, $rule ) === true ) {
			$out[] = $btn( 'quarantine', 'Quarantine', $q_confirm );
		}
		return $out;
	}

	public static function plugin_slug_from_path( $path ) {
		$plugins_rel = rtrim( MCSS_Scanner::rel( WP_PLUGIN_DIR ), '/' ) . '/';
		if ( ! MCSS_Scanner::under( $path, $plugins_rel ) ) {
			return '';
		}
		$rest = substr( $path, strlen( $plugins_rel ) );
		$slug = substr( $rest, 0, (int) strpos( $rest . '/', '/' ) );
		return preg_match( '~^[a-z0-9._-]+$~i', $slug ) && is_dir( WP_PLUGIN_DIR . '/' . $slug ) ? $slug : '';
	}

	private static function plugin_file_for_slug( $slug ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		foreach ( array_keys( get_plugins() ) as $file ) {
			if ( dirname( $file ) === $slug ) {
				return $file;
			}
		}
		return '';
	}

	private static function plugin_update_available( $slug ) {
		$up = get_site_transient( 'update_plugins' );
		if ( ! is_object( $up ) || empty( $up->response ) ) {
			return false;
		}
		foreach ( array_keys( (array) $up->response ) as $file ) {
			if ( dirname( $file ) === $slug ) {
				return true;
			}
		}
		return false;
	}

	/* ---- one-click fixes ---- */

	public static function fix( $kind, $key ) {
		$f = self::finding( $key );
		if ( ! $f ) {
			return array( 'ok' => false, 'message' => 'Finding not found. Run a new scan.' );
		}
		$allowed = false;
		foreach ( self::actions_for( $f ) as $a ) {
			if ( isset( $a['kind'] ) && $a['kind'] === $kind ) {
				$allowed = true;
			}
		}
		if ( ! $allowed ) {
			return array( 'ok' => false, 'message' => 'That fix is not available for this finding.' );
		}
		switch ( $kind ) {
			case 'repair':
				return self::repair( $key );
			case 'quarantine':
				return self::quarantine( $key );
			case 'trace_option':
				return self::trace_option( $key, substr( $f['path'], 10 ) );
			case 'delete_option':
				return self::delete_option( $key, substr( $f['path'], 10 ) );
			case 'remove_plugin':
				return self::remove_plugin( $key, $f );
			case 'update_plugin':
				return self::update_plugins( $key, array( self::plugin_slug_from_path( $f['path'] ) ) );
			case 'update_all_plugins':
				return self::update_plugins( $key, array() );
			case 'demote_user':
				return self::demote_user( $key, substr( $f['path'], 5 ) );
			case 'revoke_app_password':
				return self::revoke_app_password( $key, $f['path'] );
			case 'close_registration':
				update_option( 'users_can_register', 0 );
				update_option( 'default_role', 'subscriber' );
				MCSS_Log::add( 'fix_applied', 'registration', 'closed, default role subscriber' );
				self::resolve_finding( $key );
				return array( 'ok' => true, 'message' => 'Open registration is off and the default role is Subscriber.' );
			case 'harden_file_edit':
				$s = get_option( MCSS_Scanner::OPT_SETTINGS, array() );
				$s = is_array( $s ) ? $s : array();
				$s['h_file_edit'] = 1;
				update_option( MCSS_Scanner::OPT_SETTINGS, $s, true );
				MCSS_Log::add( 'hardening_changed', '', 'file editor off (from findings)' );
				self::resolve_finding( $key );
				return array( 'ok' => true, 'message' => 'The theme and plugin file editor is now off. Change it back on the Hardening tab if you ever need it.' );
			case 'rotate_salts':
				$r = MCSS_Scanner::rotate_salts();
				if ( $r['ok'] ) {
					self::resolve_finding( $key );
				}
				return $r;
			case 'clear_debug_log':
				return self::clear_debug_log( $key, $f['path'] );
			case 'accept_baseline':
				$b = get_option( MCSS_Scanner::OPT_BASELINE, array() );
				if ( is_array( $b ) && isset( $b['files'] ) ) {
					$abs = MCSS_Scanner::abs( $f['path'] );
					if ( is_file( $abs ) ) {
						$b['files'][ $f['path'] ] = (string) @md5_file( $abs );
						update_option( MCSS_Scanner::OPT_BASELINE, $b, false );
					}
				}
				MCSS_Log::add( 'baseline_accepted', $f['path'] );
				MCSS_Alerts::watch( true );
				self::resolve_finding( $key );
				return array( 'ok' => true, 'message' => $f['path'] . ' recorded as expected. It will be reported again if it changes.' );
		}
		return array( 'ok' => false, 'message' => 'Unknown fix.' );
	}

	/** Options WordPress itself needs are never offered for deletion. */
	private static function option_deletable( $name ) {
		static $core = array( 'siteurl', 'home', 'blogname', 'admin_email', 'active_plugins', 'template', 'stylesheet', 'db_version', 'cron', 'rewrite_rules', 'users_can_register', 'default_role', 'wp_user_roles', 'initial_db_version' );
		if ( $name === '' || strlen( $name ) > 191 || in_array( $name, $core, true ) || strpos( $name, 'mcss_' ) === 0 || strpos( $name, '_transient_' ) === 0 || strpos( $name, '_site_transient_' ) === 0 ) {
			return false;
		}
		global $wpdb;
		return in_array( $name, array( 'user_roles' ), true ) ? false : $name !== $wpdb->prefix . 'user_roles';
	}

	/**
	 * Find the PHP that reads a database option. Malware that keeps its target in the database has a reader file that
	 * looks harmless on its own, so the option name (and its stem, e.g. "_wmo" for "_wmo_src") is searched for in every
	 * PHP file on the site. Hits become high findings with their own Quarantine buttons.
	 */
	private static function trace_option( $key, $name ) {
		$needles = array( $name );
		$stem    = preg_replace( '~_(?:src|url|gw|key|cfg|conf|host|dom|domain|target|last|ts|time)$~i', '', $name );
		if ( $stem !== $name && strlen( trim( $stem, '_' ) ) >= 3 ) {
			$needles[] = $stem;
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 300 );
		}
		$roots = array( rtrim( MCSS_Scanner::norm( ABSPATH ), '/' ) );
		if ( strpos( MCSS_Scanner::norm( WP_CONTENT_DIR ) . '/', MCSS_Scanner::norm( ABSPATH ) ) !== 0 ) {
			$roots[] = MCSS_Scanner::norm( WP_CONTENT_DIR );
		}
		$qdir  = MCSS_Scanner::norm( self::dir() );
		$own   = MCSS_Scanner::norm( MCSS_FILE );
		$hits  = array();
		$count = 0;
		$start = microtime( true );
		foreach ( $roots as $root ) {
			try {
				$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::UNIX_PATHS ), \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD );
			} catch ( \Throwable $e ) {
				continue;
			}
			foreach ( $it as $x ) {
				if ( microtime( true ) - $start > 100 ) {
					return array( 'ok' => false, 'message' => 'The search ran out of time after ' . number_format( $count ) . ' files. Run it again to continue, or search over SSH: grep -rl "' . $name . '" --include=*.php .' );
				}
				$abs = MCSS_Scanner::norm( $x->getPathname() );
				if ( ! $x->isFile() || $abs === $own || strpos( $abs, $qdir . '/' ) === 0 || ! MCSS_Scanner::is_php_ext( MCSS_Scanner::ext( $x->getFilename() ) ) || $x->getSize() > 3000000 ) {
					continue;
				}
				$count++;
				$c = @file_get_contents( $abs );
				if ( ! is_string( $c ) ) {
					continue;
				}
				foreach ( $needles as $n ) {
					$pos = strpos( $c, $n );
					if ( $pos === false ) {
						continue;
					}
					$rel  = MCSS_Scanner::rel( $abs );
					$line = substr_count( $c, "\n", 0, $pos ) + 1;
					$snip = MCSS_Scanner::clean_snip( substr( $c, max( 0, $pos - 80 ), 260 ) );
					MCSS_Scanner::load_findings();
					MCSS_Scanner::add( 'high', 'option_reader', 'File refers to the malware option ' . $name, $rel, $line, $snip, 'This is the code that uses the value stored in the database. Read it, then quarantine it if it is not yours.', $name );
					$hits[] = $rel . ':' . $line;
					break;
				}
			}
		}
		MCSS_Scanner::save_findings();
		if ( ! empty( $hits ) ) {
			$run = get_option( MCSS_Scanner::OPT_RUN, array() );
			$all = get_option( MCSS_Scanner::OPT_FINDINGS, array() );
			$all = is_array( $all ) ? $all : array();
			foreach ( ( is_array( $run ) ? $run : array() ) as $k => $f ) {
				if ( $f['rule'] === 'option_reader' ) {
					$all[ $k ] = $f;
				}
			}
			update_option( MCSS_Scanner::OPT_FINDINGS, $all, false );
			delete_option( MCSS_Scanner::OPT_RUN );
		}
		MCSS_Log::add( 'option_traced', $name, count( $hits ) . ' file(s): ' . implode( ', ', array_slice( $hits, 0, 10 ) ) );
		if ( empty( $hits ) ) {
			return array( 'ok' => true, 'message' => 'No PHP file on the site mentions "' . $name . '"' . ( count( $needles ) > 1 ? ' or "' . $needles[1] . '"' : '' ) . ' (' . number_format( $count ) . ' files searched). The code that wrote it has probably been removed already. Delete the option, then check the Inventory for anything else you do not recognise.' );
		}
		return array( 'ok' => true, 'message' => count( $hits ) . ' file(s) refer to this option and have been added to the findings list as high: ' . implode( ', ', array_slice( $hits, 0, 8 ) ) . '. Reload this page to see them with their Quarantine buttons.' );
	}

	private static function delete_option( $key, $name ) {
		global $wpdb;
		if ( ! self::option_deletable( $name ) ) {
			return array( 'ok' => false, 'message' => 'That option is part of WordPress and cannot be deleted from here.' );
		}
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT option_value, autoload FROM {$wpdb->options} WHERE option_name = %s", $name ) );
		if ( ! $row ) {
			self::resolve_finding( $key );
			return array( 'ok' => true, 'message' => 'The option was already gone.' );
		}
		$items = self::items();
		$id    = strtolower( wp_generate_password( 16, false ) );
		$items[ $id ] = array( 'orig' => 'option ' . $name, 'time' => time(), 'user' => MCSS_Scanner::current_login(), 'md5' => md5( (string) $row->option_value ), 'rule' => 'db_option', 'title' => 'Database option deleted (' . size_format( strlen( (string) $row->option_value ) ) . ')', 'kind' => 'option', 'name' => $name, 'value' => (string) $row->option_value, 'autoload' => (string) $row->autoload );
		if ( strlen( (string) $row->option_value ) > 200000 ) {
			$items[ $id ]['value'] = '';
			$items[ $id ]['title'] .= ', value too large to keep';
		}
		update_option( self::OPT, $items, false );
		delete_option( $name );
		wp_cache_delete( 'alloptions', 'options' );
		foreach ( array( 'cfx_cfg', 'cfx_cfg_neg', 'cfx_last_ip', 'cfx_gw' ) as $t ) {
			delete_transient( $t );
		}
		self::resolve_finding( $key );
		MCSS_Log::add( 'option_deleted', $name );
		return array( 'ok' => true, 'message' => 'Option "' . $name . '" deleted. Its value is kept in quarantine. If you have not yet, use "Find the code that reads it" on a fresh scan, and purge the page cache so cached pages stop carrying anything it produced.' );
	}

	private static function remove_plugin( $key, $f ) {
		if ( ! MCSS_Scanner::file_mods_allowed() ) {
			return array( 'ok' => false, 'message' => 'File changes are switched off on this site (DISALLOW_FILE_MODS). Deactivate the plugin from the Plugins screen instead.' );
		}
		if ( ! function_exists( 'deactivate_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$slug = self::plugin_slug_from_path( $f['path'] );
		$file = self::plugin_file_for_slug( $slug );
		if ( $slug === '' || $slug === basename( dirname( MCSS_FILE ) ) ) {
			return array( 'ok' => false, 'message' => 'That plugin cannot be removed from here.' );
		}
		if ( ! self::ensure_dir() ) {
			return array( 'ok' => false, 'message' => 'The quarantine folder could not be created. Nothing was changed.' );
		}
		$network    = $file !== '' && is_plugin_active_for_network( $file );
		$was_active = $file !== '' && ( is_plugin_active( $file ) || $network );
		$before     = self::health();
		if ( $was_active ) {
			deactivate_plugins( $file, true, $network );
			$after = self::health();
			if ( self::broke( $before, $after ) ) {
				activate_plugin( $file, '', $network, true );
				return array( 'ok' => false, 'message' => 'The site stopped responding with the plugin deactivated (HTTP ' . $after . '), so it was reactivated. Something depends on it.' );
			}
		}
		$src    = MCSS_Scanner::norm( WP_PLUGIN_DIR . '/' . $slug );
		$id     = strtolower( wp_generate_password( 16, false ) );
		$stored = self::dir() . '/' . $id . '.dir';
		$old    = array();
		try {
			$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $src, \FilesystemIterator::SKIP_DOTS ) );
			foreach ( $it as $x ) {
				if ( $x->isFile() && MCSS_Scanner::is_php_ext( MCSS_Scanner::ext( $x->getFilename() ) ) ) {
					$old[] = $x->getPathname();
				}
			}
		} catch ( \Throwable $e ) {
			$old = array();
		}
		if ( ! @rename( $src, $stored ) ) {
			if ( $was_active ) {
				activate_plugin( $file, '', $network, true );
			}
			return array( 'ok' => false, 'message' => 'The plugin folder could not be moved (permissions). ' . ( $was_active ? 'It was reactivated.' : 'Nothing was changed.' ) );
		}
		wp_cache_delete( 'plugins', 'plugins' );
		self::forget_compiled( $old );
		$after = self::health();
		if ( self::broke( $before, $after ) ) {
			@rename( $stored, $src );
			wp_cache_delete( 'plugins', 'plugins' );
			if ( $was_active ) {
				activate_plugin( $file, '', $network, true );
			}
			return array( 'ok' => false, 'message' => 'The site stopped responding once the folder was moved (HTTP ' . $after . '), so it was put back' . ( $was_active ? ' and reactivated' : '' ) . '.' );
		}
		$items        = self::items();
		$items[ $id ] = array( 'orig' => rtrim( MCSS_Scanner::rel( $src ), '/' ) . '/', 'time' => time(), 'user' => MCSS_Scanner::current_login(), 'md5' => '', 'rule' => $f['rule'], 'title' => 'Plugin ' . $slug . ( $was_active ? ' (was active)' : '' ), 'kind' => 'dir', 'plugin_file' => $file, 'was_active' => $was_active ? 1 : 0, 'network' => $network ? 1 : 0 );
		update_option( self::OPT, $items, false );
		self::resolve_finding( $key );
		MCSS_Log::add( 'plugin_quarantined', $slug, $was_active ? 'was active' : 'was inactive' );
		MCSS_Alerts::watch( true );
		return array( 'ok' => true, 'message' => 'Plugin ' . $slug . ( $was_active ? ' deactivated and' : '' ) . ' moved to quarantine. ' . ( ( $before >= 200 && $before < 400 ) ? 'Site checked and still responding.' : 'The automatic site check could not be used here, so load the site now and confirm it is fine.' ) . ' Restore it from the Response tab if needed.' );
	}

	private static function update_plugins( $key, $slugs ) {
		if ( ! MCSS_Scanner::file_mods_allowed() ) {
			return array( 'ok' => false, 'message' => 'File changes are switched off on this site (DISALLOW_FILE_MODS).' );
		}
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		wp_update_plugins();
		$up = get_site_transient( 'update_plugins' );
		if ( ! is_object( $up ) || empty( $up->response ) ) {
			self::resolve_finding( $key );
			return array( 'ok' => true, 'message' => 'No plugin updates are waiting.' );
		}
		$files = array();
		foreach ( array_keys( (array) $up->response ) as $file ) {
			if ( empty( $slugs ) || in_array( dirname( $file ), $slugs, true ) ) {
				$files[] = $file;
			}
		}
		if ( empty( $files ) ) {
			return array( 'ok' => false, 'message' => 'No update is available for that plugin.' );
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 300 );
		}
		$before   = self::health();
		$done     = array();
		$failed   = array();
		$skin     = class_exists( 'WP_Ajax_Upgrader_Skin' ) ? new WP_Ajax_Upgrader_Skin() : new Automatic_Upgrader_Skin();
		$upgrader = new Plugin_Upgrader( $skin );
		foreach ( $files as $file ) {
			$r = $upgrader->upgrade( $file );
			if ( is_wp_error( $r ) || $r === false || $r === null ) {
				$failed[] = dirname( $file );
				continue;
			}
			$done[] = dirname( $file );
			$after  = self::health();
			if ( self::broke( $before, $after ) ) {
				MCSS_Log::add( 'plugins_updated', implode( ', ', $done ), 'stopped: site returned HTTP ' . $after . ' after ' . dirname( $file ) );
				return array( 'ok' => false, 'message' => 'Updated ' . implode( ', ', $done ) . ', but the site returned HTTP ' . $after . ' after updating ' . dirname( $file ) . ', so the run stopped. Check the site now. If it is down, deactivate that plugin from the Plugins screen or rename its folder over SFTP.' );
			}
		}
		MCSS_Log::add( 'plugins_updated', implode( ', ', $done ), $failed ? 'failed: ' . implode( ', ', $failed ) : '' );
		if ( ! empty( $done ) ) {
			self::resolve_finding( $key );
		}
		return array( 'ok' => empty( $failed ), 'message' => ( $done ? 'Updated: ' . implode( ', ', $done ) . '. ' : '' ) . ( $failed ? 'Could not update: ' . implode( ', ', $failed ) . '. Try those from the Plugins screen.' : 'Site checked and still responding.' ) );
	}

	private static function demote_user( $key, $login ) {
		global $wpdb;
		$login = preg_replace( '~ / .*$~', '', $login );
		$id    = (int) $wpdb->get_var( $wpdb->prepare( "SELECT ID FROM {$wpdb->users} WHERE user_login = %s", $login ) );
		$user  = $id ? new WP_User( $id ) : null;
		if ( ! $user || ! $user->ID ) {
			return array( 'ok' => false, 'message' => 'User not found.' );
		}
		if ( (int) $user->ID === get_current_user_id() ) {
			return array( 'ok' => false, 'message' => 'You cannot remove your own admin rights from here.' );
		}
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return array( 'ok' => false, 'message' => 'That account is a network super admin. Change it from the Network Users screen.' );
		}
		$old = implode( ',', (array) $user->roles );
		$user->set_role( 'subscriber' );
		if ( class_exists( 'WP_Session_Tokens' ) ) {
			WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
		}
		$apps = 0;
		if ( class_exists( 'WP_Application_Passwords' ) ) {
			$apps = count( (array) WP_Application_Passwords::get_user_application_passwords( $user->ID ) );
			WP_Application_Passwords::delete_all_application_passwords( $user->ID );
		}
		MCSS_Log::add( 'user_demoted', $user->user_login, ( $old !== '' ? $old : 'none' ) . ' -> subscriber, sessions ended, ' . $apps . ' application passwords revoked' );
		self::resolve_finding( $key );
		return array( 'ok' => true, 'message' => $user->user_login . ' is now a Subscriber and logged out everywhere' . ( $apps ? ', with ' . $apps . ' application password(s) revoked' : '' ) . '. Delete the account from the Users screen once you have confirmed it is not needed.' );
	}

	private static function revoke_app_password( $key, $path ) {
		$m = array();
		if ( ! class_exists( 'WP_Application_Passwords' ) || ! preg_match( '~^user:([^/]+) / (.+)$~', $path, $m ) ) {
			return array( 'ok' => false, 'message' => 'Could not identify that application password.' );
		}
		$user = get_user_by( 'login', trim( $m[1] ) );
		if ( ! $user ) {
			return array( 'ok' => false, 'message' => 'User not found.' );
		}
		$n = 0;
		foreach ( (array) WP_Application_Passwords::get_user_application_passwords( $user->ID ) as $ap ) {
			$name = isset( $ap['name'] ) ? (string) $ap['name'] : 'unnamed';
			if ( $name === trim( $m[2] ) && ! empty( $ap['uuid'] ) ) {
				WP_Application_Passwords::delete_application_password( $user->ID, $ap['uuid'] );
				$n++;
			}
		}
		MCSS_Log::add( 'app_password_revoked', $user->user_login, trim( $m[2] ) . ' (' . $n . ')' );
		self::resolve_finding( $key );
		return array( 'ok' => $n > 0, 'message' => $n ? 'Application password revoked.' : 'That application password was already gone.' );
	}

	private static function clear_debug_log( $key, $rel ) {
		if ( ! MCSS_Scanner::file_mods_allowed() ) {
			return array( 'ok' => false, 'message' => 'File changes are switched off on this site (DISALLOW_FILE_MODS).' );
		}
		$abs = MCSS_Scanner::abs( $rel );
		if ( basename( $abs ) !== 'debug.log' || ! is_file( $abs ) || ! is_writable( $abs ) ) {
			return array( 'ok' => false, 'message' => 'debug.log was not found or is not writable.' );
		}
		if ( ! self::ensure_dir() ) {
			return array( 'ok' => false, 'message' => 'The quarantine folder could not be created. Nothing was changed.' );
		}
		$id = strtolower( wp_generate_password( 16, false ) );
		if ( ! @copy( $abs, self::dir() . '/' . $id . '.quarantined' ) ) {
			return array( 'ok' => false, 'message' => 'Could not keep a copy of the log. Nothing was changed.' );
		}
		@file_put_contents( $abs, '' );
		$items        = self::items();
		$items[ $id ] = array( 'orig' => $rel, 'time' => time(), 'user' => MCSS_Scanner::current_login(), 'md5' => '', 'rule' => 'exposed_debuglog', 'title' => 'debug.log contents before it was emptied', 'kind' => 'replaced' );
		update_option( self::OPT, $items, false );
		MCSS_Log::add( 'debug_log_cleared', $rel );
		self::resolve_finding( $key );
		return array( 'ok' => true, 'message' => 'debug.log emptied. The old contents are in quarantine. To stop it filling up again, set WP_DEBUG_LOG to false in wp-config.php.' );
	}

	private static function rmdir_recursive( $dir ) {
		$real = MCSS_Scanner::norm( (string) realpath( $dir ) );
		if ( $real === '' || strpos( $real, MCSS_Scanner::norm( (string) realpath( self::dir() ) ) . '/' ) !== 0 ) {
			return;
		}
		$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $real, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::CHILD_FIRST );
		foreach ( $it as $x ) {
			$x->isDir() ? @rmdir( $x->getPathname() ) : @unlink( $x->getPathname() );
		}
		@rmdir( $real );
	}

	/** @return true|string True, or the reason it is refused. */
	private static $memo = array();
	private static $ref_cache = array();

	private static function ref_text( $file ) {
		if ( ! isset( self::$ref_cache[ $file ] ) ) {
			self::$ref_cache[ $file ] = is_file( $file ) ? strtolower( (string) @file_get_contents( $file, false, null, 0, 300000 ) ) : '';
		}
		return self::$ref_cache[ $file ];
	}

	public static function can_quarantine( $rel, $rule ) {
		$mk = $rule . '|' . $rel;
		if ( ! isset( self::$memo[ $mk ] ) ) {
			self::$memo[ $mk ] = self::can_quarantine_uncached( $rel, $rule );
		}
		return self::$memo[ $mk ];
	}

	private static function can_quarantine_uncached( $rel, $rule ) {
		if ( ! MCSS_Scanner::file_mods_allowed() ) {
			return 'File changes are switched off on this site (DISALLOW_FILE_MODS), so the scanner will not move files.';
		}
		$abs  = MCSS_Scanner::abs( $rel );
		$name = basename( $rel );
		if ( ! is_file( $abs ) ) {
			return 'The file no longer exists.';
		}
		$real = MCSS_Scanner::norm( (string) realpath( $abs ) );
		$root = MCSS_Scanner::norm( (string) realpath( ABSPATH ) );
		$cont = MCSS_Scanner::norm( (string) realpath( WP_CONTENT_DIR ) );
		if ( $real === '' || ( strpos( $real, $root . '/' ) !== 0 && strpos( $real, $cont . '/' ) !== 0 ) ) {
			return 'The file is outside this WordPress install.';
		}
		if ( $real === MCSS_Scanner::config_path() || $real === MCSS_Scanner::norm( (string) realpath( MCSS_FILE ) ) || ( $name === '.htaccess' && dirname( $real ) === $root ) || $rel === 'index.php' ) {
			return 'This file is required for the site to run.';
		}

		$mu_rel  = rtrim( MCSS_Scanner::rel( WPMU_PLUGIN_DIR ), '/' ) . '/';
		$allowed = false;
		if ( MCSS_Scanner::under( $rel, MCSS_Scanner::uploads_rel() ) ) {
			$allowed = true;
		} elseif ( MCSS_Scanner::under( $rel, $mu_rel ) && strpos( substr( $rel, strlen( $mu_rel ) ), '/' ) === false ) {
			$allowed = true;
			foreach ( MCSS_Scanner::files_in( WPMU_PLUGIN_DIR, false, 200 ) as $other ) {
				if ( basename( $other ) !== $name && strpos( self::ref_text( $other ), strtolower( $name ) ) !== false ) {
					return 'Another must-use plugin (' . basename( $other ) . ') refers to this file, so removing it could take the site down. Remove it by hand over SFTP.';
				}
			}
		} elseif ( in_array( $rule, array( 'core_unknown', 'core_unknown_js', 'root_unknown', 'plugin_extra', 'php_in_ico', 'phpinfo', 'double_ext', 'exposed_config', 'exposed_sql', 'exposed_env', 'exposed_dbtool', 'exposed_archive' ), true ) ) {
			$allowed = true;
		} elseif ( self::inactive_component( $rel ) ) {
			$allowed = true;
		}
		if ( ! $allowed ) {
			return 'This file belongs to an active plugin or theme. Moving it could break the site. Reinstall that plugin or theme from a clean copy instead.';
		}

		$refs = array( MCSS_Scanner::config_path(), $root . '/.htaccess', $root . '/.user.ini', $root . '/php.ini' );
		foreach ( $refs as $cfg ) {
			if ( $cfg !== '' && $cfg !== $real && strpos( self::ref_text( $cfg ), strtolower( $name ) ) !== false ) {
				return basename( $cfg ) . ' refers to this file (common for firewall loaders), so removing it could take the site down. Remove that reference first.';
			}
		}
		return true;
	}

	public static function quarantine( $key ) {
		$f = self::finding( $key );
		if ( ! $f ) {
			return array( 'ok' => false, 'message' => 'Finding not found. Run a new scan.' );
		}
		$can = self::can_quarantine( $f['path'], $f['rule'] );
		if ( $can !== true ) {
			return array( 'ok' => false, 'message' => $can . ' Nothing was changed.' );
		}
		if ( ! self::ensure_dir() ) {
			return array( 'ok' => false, 'message' => 'The quarantine folder could not be created. Nothing was changed.' );
		}
		$abs    = MCSS_Scanner::abs( $f['path'] );
		$id     = strtolower( wp_generate_password( 16, false ) );
		$stored = self::dir() . '/' . $id . '.quarantined';
		$md5    = (string) @md5_file( $abs );
		$perms  = (int) ( @fileperms( $abs ) & 0777 );
		$before = self::health();

		if ( ! @rename( $abs, $stored ) ) {
			if ( @filesize( $abs ) > 50000000 || ! @copy( $abs, $stored ) || @md5_file( $stored ) !== $md5 || ! @unlink( $abs ) ) {
				@unlink( $stored );
				return array( 'ok' => false, 'message' => 'The file could not be moved (permissions). Nothing was changed.' );
			}
		}
		@chmod( $stored, 0600 );
		self::forget_compiled( array( $abs ) );

		$after = self::health();
		if ( self::broke( $before, $after ) ) {
			@rename( $stored, $abs );
			if ( $perms ) {
				@chmod( $abs, $perms );
			}
			$back = is_file( $abs ) && @md5_file( $abs ) === $md5;
			return array( 'ok' => false, 'message' => $back ? 'The site stopped responding once the file was moved (HTTP ' . $after . '), so it was put straight back and verified. Something depends on it.' : 'The site stopped responding once the file was moved (HTTP ' . $after . ') and putting it back could NOT be confirmed. Restore ' . $f['path'] . ' by hand from wp-content/mcss-quarantine/' . $id . '.quarantined right now.' );
		}

		$items        = self::items();
		$items[ $id ] = array( 'orig' => $f['path'], 'time' => time(), 'user' => MCSS_Scanner::current_login(), 'md5' => $md5, 'rule' => $f['rule'], 'title' => $f['title'], 'kind' => 'quarantine', 'perms' => $perms );
		update_option( self::OPT, $items, false );
		self::resolve_finding( $key );
		MCSS_Log::add( 'file_quarantined', $f['path'], $f['title'] );
		MCSS_Alerts::watch( true );
		$note = ( $before >= 200 && $before < 400 ) ? ' Site checked and still responding.' : ' The automatic site check could not be used here (the home page answered HTTP ' . $before . ' before the change), so load the site now and confirm it is fine.';
		return array( 'ok' => true, 'message' => $f['path'] . ' moved to quarantine.' . $note . ' You can restore it from the Response tab.' );
	}

	public static function restore( $id ) {
		if ( ! MCSS_Scanner::file_mods_allowed() ) {
			return array( 'ok' => false, 'message' => 'File changes are switched off on this site (DISALLOW_FILE_MODS).' );
		}
		$items = self::items();
		if ( ! isset( $items[ $id ] ) ) {
			return array( 'ok' => false, 'message' => 'Quarantine entry not found.' );
		}
		$stored = self::dir() . '/' . $id . '.quarantined';
		$dest   = MCSS_Scanner::abs( $items[ $id ]['orig'] );
		if ( $items[ $id ]['kind'] === 'option' ) {
			if ( $items[ $id ]['value'] === '' ) {
				return array( 'ok' => false, 'message' => 'The value was too large to keep, so this option cannot be restored.' );
			}
			update_option( $items[ $id ]['name'], $items[ $id ]['value'], $items[ $id ]['autoload'] === 'yes' || $items[ $id ]['autoload'] === 'on' );
			MCSS_Log::add( 'option_restored', $items[ $id ]['name'] );
			unset( $items[ $id ] );
			update_option( self::OPT, $items, false );
			return array( 'ok' => true, 'message' => 'Option restored.' );
		}
		if ( $items[ $id ]['kind'] === 'dir' ) {
			$stored = self::dir() . '/' . $id . '.dir';
			$dest   = rtrim( $dest, '/' );
			if ( ! is_dir( $stored ) ) {
				return array( 'ok' => false, 'message' => 'The quarantined plugin folder is missing from disk.' );
			}
			if ( file_exists( $dest ) ) {
				return array( 'ok' => false, 'message' => 'A folder already exists at the original location. Nothing was changed.' );
			}
			if ( ! @rename( $stored, $dest ) ) {
				return array( 'ok' => false, 'message' => 'Could not move the folder back (permissions).' );
			}
			wp_cache_delete( 'plugins', 'plugins' );
			$msg = 'Plugin folder restored.';
			if ( ! empty( $items[ $id ]['was_active'] ) && ! empty( $items[ $id ]['plugin_file'] ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
				$r   = activate_plugin( $items[ $id ]['plugin_file'], '', ! empty( $items[ $id ]['network'] ), true );
				$msg = is_wp_error( $r ) ? 'Plugin folder restored but it could not be reactivated: ' . $r->get_error_message() : 'Plugin folder restored and reactivated.';
			}
			MCSS_Log::add( 'plugin_restored', $items[ $id ]['orig'] );
			unset( $items[ $id ] );
			update_option( self::OPT, $items, false );
			MCSS_Alerts::watch( true );
			return array( 'ok' => true, 'message' => $msg );
		}
		if ( ! is_file( $stored ) ) {
			return array( 'ok' => false, 'message' => 'The quarantined copy is missing from disk.' );
		}
		if ( $items[ $id ]['kind'] === 'quarantine' && file_exists( $dest ) ) {
			return array( 'ok' => false, 'message' => 'A file already exists at the original location. Nothing was changed.' );
		}
		if ( ! is_dir( dirname( $dest ) ) ) {
			return array( 'ok' => false, 'message' => 'The original folder no longer exists. Nothing was changed.' );
		}
		if ( $items[ $id ]['kind'] === 'replaced' ) {
			if ( ! @copy( $stored, $dest ) ) {
				return array( 'ok' => false, 'message' => 'Could not write to the original location.' );
			}
			@unlink( $stored );
		} elseif ( ! @rename( $stored, $dest ) ) {
			return array( 'ok' => false, 'message' => 'Could not move the file back (permissions).' );
		}
		@chmod( $dest, ! empty( $items[ $id ]['perms'] ) ? (int) $items[ $id ]['perms'] : 0644 );
		MCSS_Log::add( 'file_restored', $items[ $id ]['orig'] );
		unset( $items[ $id ] );
		update_option( self::OPT, $items, false );
		MCSS_Alerts::watch( true );
		return array( 'ok' => true, 'message' => 'File restored to its original location.' );
	}

	public static function purge( $id ) {
		$items = self::items();
		if ( ! isset( $items[ $id ] ) || ! preg_match( '~^[a-z0-9]{16}$~', $id ) ) {
			return array( 'ok' => false, 'message' => 'Quarantine entry not found.' );
		}
		if ( $items[ $id ]['kind'] === 'dir' ) {
			self::rmdir_recursive( self::dir() . '/' . $id . '.dir' );
		} elseif ( $items[ $id ]['kind'] !== 'option' ) {
			@unlink( self::dir() . '/' . $id . '.quarantined' );
		}
		MCSS_Log::add( 'quarantine_deleted', $items[ $id ]['orig'] );
		unset( $items[ $id ] );
		update_option( self::OPT, $items, false );
		return array( 'ok' => true, 'message' => 'Deleted for good.' );
	}

	/** Replace a modified core or wordpress.org plugin file with the official one, verified by checksum before it is written. */
	public static function repair( $key ) {
		$f = self::finding( $key );
		if ( ! $f || ! in_array( $f['rule'], array( 'core_modified', 'plugin_modified' ), true ) ) {
			return array( 'ok' => false, 'message' => 'Finding not found. Run a new scan.' );
		}
		if ( ! MCSS_Scanner::file_mods_allowed() ) {
			return array( 'ok' => false, 'message' => 'File changes are switched off on this site (DISALLOW_FILE_MODS). Nothing was changed.' );
		}
		$algo = 'md5';
		$rel  = $f['path'];
		$abs  = MCSS_Scanner::abs( $rel );
		if ( ! is_file( $abs ) || ! is_writable( $abs ) ) {
			return array( 'ok' => false, 'message' => 'The file is missing or not writable by PHP. Nothing was changed.' );
		}

		if ( $f['rule'] === 'core_modified' ) {
			$sums = MCSS_Scanner::core_sums();
			if ( ! $sums || ! isset( $sums[ $rel ] ) ) {
				return array( 'ok' => false, 'message' => 'Official checksums are not available right now. Nothing was changed.' );
			}
			$expected   = (array) $sums[ $rel ];
			$wp_version = '';
			include ABSPATH . WPINC . '/version.php';
			$url = 'https://core.svn.wordpress.org/tags/' . rawurlencode( $wp_version ) . '/' . str_replace( '%2F', '/', rawurlencode( $rel ) );
		} else {
			$plugins_rel = rtrim( MCSS_Scanner::rel( WP_PLUGIN_DIR ), '/' ) . '/';
			$rest        = substr( $rel, strlen( $plugins_rel ) );
			$slug        = substr( $rest, 0, (int) strpos( $rest, '/' ) );
			$inner       = substr( $rest, strlen( $slug ) + 1 );
			$version     = '';
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			foreach ( get_plugins() as $file => $data ) {
				if ( dirname( $file ) === $slug ) {
					$version = (string) $data['Version'];
					break;
				}
			}
			if ( $slug === '' || $version === '' ) {
				return array( 'ok' => false, 'message' => 'Could not work out the plugin and version. Nothing was changed.' );
			}
			$resp = wp_remote_get( 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json', array( 'timeout' => 10 ) );
			$data = is_wp_error( $resp ) ? null : json_decode( wp_remote_retrieve_body( $resp ), true );
			if ( ! is_array( $data ) || ! isset( $data['files'][ $inner ]['md5'] ) ) {
				return array( 'ok' => false, 'message' => 'Official checksums are not available for this file. Nothing was changed.' );
			}
			if ( ! empty( $data['files'][ $inner ]['sha256'] ) ) {
				$algo     = 'sha256';
				$expected = (array) $data['files'][ $inner ]['sha256'];
			} else {
				$expected = (array) $data['files'][ $inner ]['md5'];
			}
			$url      = 'https://plugins.svn.wordpress.org/' . rawurlencode( $slug ) . '/tags/' . rawurlencode( $version ) . '/' . str_replace( '%2F', '/', rawurlencode( $inner ) );
		}

		$resp = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $resp ) || (int) wp_remote_retrieve_response_code( $resp ) !== 200 ) {
			return array( 'ok' => false, 'message' => 'The official copy could not be downloaded. Nothing was changed. Reinstall from Dashboard > Updates or the Plugins screen instead.' );
		}
		$body = (string) wp_remote_retrieve_body( $resp );
		if ( ! in_array( hash( $algo, $body ), $expected, true ) ) {
			return array( 'ok' => false, 'message' => 'The downloaded file did not match the official checksum, so it was not used. Nothing was changed.' );
		}
		if ( ! self::ensure_dir() ) {
			return array( 'ok' => false, 'message' => 'The quarantine folder could not be created, so there was nowhere to keep the old copy. Nothing was changed.' );
		}

		$id     = strtolower( wp_generate_password( 16, false ) );
		$stored = self::dir() . '/' . $id . '.quarantined';
		if ( ! @copy( $abs, $stored ) ) {
			return array( 'ok' => false, 'message' => 'Could not keep a copy of the current file. Nothing was changed.' );
		}
		$before = self::health();
		$perms  = @fileperms( $abs );
		$tmp    = $abs . '.mcss-' . strtolower( wp_generate_password( 8, false ) ) . '.tmp';
		$ok     = @file_put_contents( $tmp, $body, LOCK_EX ) === strlen( $body );
		if ( $ok ) {
			if ( $perms ) {
				@chmod( $tmp, $perms & 0777 );
			}
			$ok = @rename( $tmp, $abs );
		}
		if ( ! $ok ) {
			@unlink( $tmp );
			@unlink( $stored );
			return array( 'ok' => false, 'message' => 'The clean file could not be written. Nothing was changed.' );
		}
		self::forget_compiled( array( $abs ) );
		$after = self::health();
		if ( self::broke( $before, $after ) ) {
			@copy( $stored, $abs );
			if ( @md5_file( $abs ) === @md5_file( $stored ) ) {
				@unlink( $stored );
				return array( 'ok' => false, 'message' => 'The site stopped responding after the swap (HTTP ' . $after . '), so the previous file was put back and verified.' );
			}
			return array( 'ok' => false, 'message' => 'The site stopped responding after the swap (HTTP ' . $after . ') and putting the previous file back could NOT be confirmed. The previous copy is at wp-content/mcss-quarantine/' . $id . '.quarantined.' );
		}

		$items        = self::items();
		$items[ $id ] = array( 'orig' => $rel, 'time' => time(), 'user' => MCSS_Scanner::current_login(), 'md5' => (string) @md5_file( $stored ), 'rule' => $f['rule'], 'title' => 'Modified copy replaced with the official file', 'kind' => 'replaced' );
		update_option( self::OPT, $items, false );
		self::resolve_finding( $key );
		MCSS_Log::add( 'file_repaired', $rel );
		MCSS_Alerts::watch( true );
		return array( 'ok' => true, 'message' => $rel . ' replaced with the official file (checksum verified). The modified copy is kept in quarantine so you can inspect it.' );
	}
}

/* =========================================================================
 * Hardening switches. Runtime filters only, all reversible, all off by default.
 * Emergency off: define( 'MCSS_DISABLE_HARDENING', true ); in wp-config.php
 * ======================================================================= */

final class MCSS_Harden {

	public static function boot() {
		if ( defined( 'MCSS_DISABLE_HARDENING' ) && MCSS_DISABLE_HARDENING ) {
			return;
		}
		$s = MCSS_Scanner::settings();

		if ( ! empty( $s['h_file_edit'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
		if ( ! empty( $s['h_xmlrpc'] ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter(
				'xmlrpc_methods',
				function ( $methods ) {
					unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'], $methods['system.multicall'] );
					return $methods;
				}
			);
			add_filter(
				'wp_headers',
				function ( $headers ) {
					unset( $headers['X-Pingback'] );
					return $headers;
				}
			);
		}
		if ( ! empty( $s['h_enum'] ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'block_author_scan' ), 1 );
			add_filter( 'rest_endpoints', array( __CLASS__, 'hide_rest_users' ) );
			add_filter(
				'wp_sitemaps_add_provider',
				function ( $provider, $name ) {
					return $name === 'users' ? false : $provider;
				},
				10,
				2
			);
		}
		if ( ! empty( $s['h_app_pw'] ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}
		if ( ! empty( $s['h_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		if ( ! empty( $s['h_headers'] ) ) {
			add_action( 'send_headers', array( __CLASS__, 'headers' ) );
		}
	}

	public static function block_author_scan() {
		if ( isset( $_GET['author'] ) && ! is_user_logged_in() && ! is_admin() ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	public static function hide_rest_users( $endpoints ) {
		if ( ! is_user_logged_in() ) {
			foreach ( array_keys( $endpoints ) as $route ) {
				if ( strpos( $route, '/wp/v2/users' ) === 0 ) {
					unset( $endpoints[ $route ] );
				}
			}
		}
		return $endpoints;
	}

	public static function headers() {
		if ( headers_sent() ) {
			return;
		}
		$have = strtolower( implode( "\n", headers_list() ) );
		foreach ( array( 'X-Content-Type-Options' => 'nosniff', 'X-Frame-Options' => 'SAMEORIGIN', 'Referrer-Policy' => 'strict-origin-when-cross-origin' ) as $k => $v ) {
			if ( strpos( $have, strtolower( $k ) . ':' ) === false ) {
				header( $k . ': ' . $v );
			}
		}
	}

	public static function htaccess_supported() {
		$sw = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : '';
		return (bool) preg_match( '~apache|litespeed~i', $sw );
	}

	/** Add or remove the "no PHP in uploads" rule. Tested against a probe file and reverted if uploads stop being served. */
	public static function uploads_rule( $enable ) {
		$u = wp_upload_dir( null, false );
		if ( empty( $u['basedir'] ) || empty( $u['baseurl'] ) || ! is_dir( $u['basedir'] ) || ! is_writable( $u['basedir'] ) ) {
			return 'The uploads folder is not writable.';
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		if ( ! MCSS_Scanner::file_mods_allowed() ) {
			return 'File changes are switched off on this site (DISALLOW_FILE_MODS).';
		}
		$ht = $u['basedir'] . '/.htaccess';
		if ( ! $enable ) {
			if ( is_file( $ht ) ) {
				insert_with_markers( $ht, 'Relish Security', array() );
			}
			return true;
		}
		if ( ! self::htaccess_supported() ) {
			return 'This server does not read .htaccess files (nginx), so the rule would do nothing. Ask the host to block PHP execution in uploads instead.';
		}
		foreach ( (array) glob( $u['basedir'] . '/mcss-probe-*.txt' ) as $stale ) {
			@unlink( $stale ); // Left behind only if an earlier request died half way.
		}
		$probe = 'mcss-probe-' . strtolower( wp_generate_password( 10, false ) ) . '.txt';
		@file_put_contents( $u['basedir'] . '/' . $probe, 'ok' );
		$get = function () use ( $u, $probe ) {
			$r = wp_remote_get( $u['baseurl'] . '/' . $probe, array( 'timeout' => 8, 'sslverify' => apply_filters( 'https_local_ssl_verify', false ) ) );
			return is_wp_error( $r ) ? 0 : (int) wp_remote_retrieve_response_code( $r );
		};
		$before = $get();
		if ( $before !== 200 ) {
			@unlink( $u['basedir'] . '/' . $probe );
			return 'Could not confirm that uploads are reachable before the change (HTTP ' . $before . '), so nothing was changed.';
		}
		$rules = array(
			'<FilesMatch "\.(?i:php[0-9]?|phtml|pht|phar)$">',
			'<IfModule mod_authz_core.c>',
			'Require all denied',
			'</IfModule>',
			'<IfModule !mod_authz_core.c>',
			'Order allow,deny',
			'Deny from all',
			'</IfModule>',
			'</FilesMatch>',
		);
		insert_with_markers( $ht, 'Relish Security', $rules );
		$after = $get();
		@unlink( $u['basedir'] . '/' . $probe );
		if ( $after !== 200 ) {
			insert_with_markers( $ht, 'Relish Security', array() );
			return 'Uploads stopped being served after the rule was added (HTTP ' . $after . '), so it was removed again. This host does not allow that directive.';
		}
		return true;
	}
}

/* =========================================================================
 * Client report: plain-language summary of plugins, licences and administrators
 * ======================================================================= */

final class MCSS_Report {

	/** Option keys that hold a licence for well-known premium plugins. Empty value = licence missing. */
	private static function licence_keys() {
		return apply_filters(
			'mcss_licence_keys',
			array(
				'advanced-custom-fields-pro'     => array( 'acf_pro_license' ),
				'gravityforms'                   => array( 'rg_gforms_key' ),
				'oxygen'                         => array( 'oxygen_license_key' ),
				'oxygen-3'                       => array( 'oxygen_license_key' ),
				'oxyextras'                      => array( 'oxyextras_license_key' ),
				'wp-grid-builder'                => array( 'wpgb_license_key' ),
				'relevanssi-premium'             => array( 'relevanssi_api_key' ),
				'wp-all-import-pro'              => array( 'PMXI_Plugin_license_key', 'pmxi_license_key' ),
				'wp-all-export-pro'              => array( 'PMXE_Plugin_license_key', 'pmxe_license_key' ),
				'shortpixel-image-optimiser'     => array( 'wp-short-pixel-apiKey' ),
				'custom-twitter-feeds-pro'       => array( 'ctf_license_key' ),
				'the-events-calendar-pro'        => array( 'pue_install_key_events_calendar_pro' ),
				'wp-rocket'                      => array( 'wp_rocket_settings' ),
				'elementor-pro'                  => array( 'elementor_pro_license_key' ),
				'wpforms'                        => array( 'wpforms_license' ),
				'seo-by-rank-math-pro'           => array( 'rank_math_connect_data' ),
			)
		);
	}

	private static function licence_present( $slug ) {
		$keys = self::licence_keys();
		if ( ! isset( $keys[ $slug ] ) ) {
			return null; // unknown
		}
		foreach ( $keys[ $slug ] as $k ) {
			$v = get_option( $k );
			if ( is_array( $v ) ) {
				$v = implode( '', array_map( 'strval', array_filter( $v, 'is_scalar' ) ) );
			}
			if ( is_string( $v ) && trim( $v ) !== '' ) {
				return true;
			}
		}
		if ( strpos( $slug, 'gravity' ) === 0 || strpos( $slug, 'gp-' ) === 0 || $slug === 'spellbook' ) {
			return trim( (string) get_option( 'rg_gforms_key' ) ) !== '' || trim( (string) get_option( 'gwp_license_key' ) ) !== '';
		}
		return false;
	}

	/** wordpress.org "last updated" for free plugins, cached a day. */
	private static function wporg_updated( $slug ) {
		$cache = get_option( 'mcss_report_cache', array() );
		$cache = is_array( $cache ) ? $cache : array();
		if ( isset( $cache[ $slug ] ) && $cache[ $slug ]['t'] > time() - DAY_IN_SECONDS ) {
			return $cache[ $slug ];
		}
		$r    = array( 't' => time(), 'on_org' => false, 'updated' => 0, 'latest' => '', 'closed' => false );
		$resp = wp_remote_get( 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode( $slug ) . '&request[fields][sections]=0&request[fields][versions]=0&request[fields][screenshots]=0&request[fields][banners]=0&request[fields][icons]=0', array( 'timeout' => 6 ) );
		if ( ! is_wp_error( $resp ) ) {
			$j = json_decode( wp_remote_retrieve_body( $resp ), true );
			if ( is_array( $j ) && empty( $j['error'] ) && ! empty( $j['version'] ) ) {
				$r['on_org']  = true;
				$r['latest']  = (string) $j['version'];
				$r['updated'] = ! empty( $j['last_updated'] ) ? (int) strtotime( (string) $j['last_updated'] ) : 0;
			} elseif ( is_array( $j ) && isset( $j['error'] ) && $j['error'] === 'closed' ) {
				$r['on_org'] = true;
				$r['closed'] = true;
			}
		} else {
			$r['t'] = time() - DAY_IN_SECONDS + HOUR_IN_SECONDS; // retry in an hour
		}
		$cache[ $slug ] = $r;
		if ( count( $cache ) > 300 ) {
			$cache = array_slice( $cache, -250, null, true );
		}
		update_option( 'mcss_report_cache', $cache, false );
		return $r;
	}

	public static function plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( function_exists( 'wp_update_plugins' ) ) {
			wp_update_plugins();
		}
		$up   = get_site_transient( 'update_plugins' );
		$resp = ( is_object( $up ) && ! empty( $up->response ) ) ? (array) $up->response : array();
		$noup = ( is_object( $up ) && ! empty( $up->no_update ) ) ? (array) $up->no_update : array();
		$vuln = get_option( 'mcss_vuln_cache', array() );
		$vuln = is_array( $vuln ) ? $vuln : array();
		$rows = array();
		$own  = plugin_basename( MCSS_FILE );
		$n    = 0;

		foreach ( get_plugins() as $file => $data ) {
			if ( $file === $own || ++$n > 120 ) {
				continue;
			}
			$slug    = dirname( $file ) === '.' ? basename( $file, '.php' ) : dirname( $file );
			$version = isset( $data['Version'] ) ? (string) $data['Version'] : '';
			$active  = is_plugin_active( $file ) || is_plugin_active_for_network( $file );
			$row     = array(
				'name'    => isset( $data['Name'] ) ? (string) $data['Name'] : $slug,
				'slug'    => $slug,
				'version' => $version,
				'active'  => $active,
				'latest'  => '',
				'status'  => '',
				'state'   => 'ok',
				'action'  => '',
				'vulns'   => 0,
			);
			$org = self::wporg_updated( $slug );
			$vk  = 'plugin|' . $slug . '|' . $version;
			if ( isset( $vuln[ $vk ]['r']['vulns'] ) ) {
				$row['vulns'] = count( (array) $vuln[ $vk ]['r']['vulns'] );
			}

			if ( isset( $resp[ $file ] ) ) {
				$new     = isset( $resp[ $file ]->new_version ) ? (string) $resp[ $file ]->new_version : '';
				$package = isset( $resp[ $file ]->package ) ? (string) $resp[ $file ]->package : '';
				$row['latest'] = $new;
				if ( $package === '' ) {
					$row['state']  = 'blocked';
					$row['status'] = 'Update ' . $new . ' is available but cannot be installed: the plugin reports no download package, which means its licence is missing, expired, or for another site.';
					$row['action'] = 'Renew or enter the licence, then update.';
				} else {
					$row['state']  = 'update';
					$row['status'] = 'Update available (' . $new . ').';
					$row['action'] = 'Update.';
				}
			} elseif ( isset( $noup[ $file ] ) ) {
				$row['status'] = 'Up to date.';
			} elseif ( $org['on_org'] && $org['closed'] ) {
				$row['state']  = 'closed';
				$row['status'] = 'This plugin has been removed from the WordPress directory and will never be updated again.';
				$row['action'] = 'Replace it.';
			} elseif ( $org['on_org'] && $org['latest'] !== '' ) {
				$row['latest'] = $org['latest'];
				if ( version_compare( $version, $org['latest'], '<' ) ) {
					$row['state']  = 'update';
					$row['status'] = 'Update available (' . $org['latest'] . ').';
					$row['action'] = 'Update.';
				} else {
					$row['status'] = 'Up to date.';
				}
			} else {
				$lic = self::licence_present( $slug );
				if ( $lic === false ) {
					$row['state']  = 'blocked';
					$row['status'] = 'Premium plugin with no licence key saved on this site, so it is not receiving updates.';
					$row['action'] = 'Enter the licence key, or replace the plugin.';
				} elseif ( $lic === true ) {
					$row['status'] = 'Premium plugin, licence key present. WordPress has not reported an update for it.';
				} else {
					$row['state']  = 'unknown';
					$row['status'] = 'Premium or custom plugin. It is not in the WordPress directory and did not report an update check, so its licence and update status could not be confirmed.';
					$row['action'] = 'Confirm the licence is active in the plugin\'s own settings.';
				}
			}
			if ( $org['on_org'] && $org['updated'] && $org['updated'] < time() - 2 * YEAR_IN_SECONDS && $row['state'] !== 'closed' ) {
				$row['status'] .= ' Its developer has not released anything since ' . gmdate( 'M Y', $org['updated'] ) . '.';
				if ( $row['state'] === 'ok' ) {
					$row['state']  = 'stale';
					$row['action'] = 'Plan a replacement.';
				}
			}
			if ( $row['vulns'] > 0 ) {
				$row['status'] = $row['vulns'] . ' known security ' . ( $row['vulns'] === 1 ? 'vulnerability' : 'vulnerabilities' ) . ' in this version. ' . $row['status'];
				if ( $row['state'] === 'ok' || $row['state'] === 'unknown' || $row['state'] === 'stale' ) {
					$row['state'] = 'update';
				}
			}
			$rows[] = $row;
		}
		$order = array( 'blocked' => 0, 'closed' => 1, 'update' => 2, 'unknown' => 3, 'stale' => 4, 'ok' => 5 );
		usort(
			$rows,
			function ( $a, $b ) use ( $order ) {
				if ( $order[ $a['state'] ] !== $order[ $b['state'] ] ) {
					return $order[ $a['state'] ] - $order[ $b['state'] ];
				}
				return strcasecmp( $a['name'], $b['name'] );
			}
		);
		return $rows;
	}

	public static function admins() {
		global $wpdb;
		$ids = array_slice( MCSS_Scanner::privileged_user_ids(), 0, 300 );
		if ( empty( $ids ) ) {
			return array();
		}
		$in   = implode( ',', array_map( 'intval', $ids ) );
		$rows = $wpdb->get_results( "SELECT ID, user_login, display_name, user_email, user_registered FROM {$wpdb->users} WHERE ID IN ({$in}) ORDER BY user_login ASC" );
		$out  = array();
		$log  = MCSS_Log::table();
		$old  = $wpdb->suppress_errors( true );
		foreach ( (array) $rows as $u ) {
			$last  = $wpdb->get_var( $wpdb->prepare( "SELECT MAX(created) FROM {$log} WHERE event = 'login' AND user_login = %s", $u->user_login ) );
			$sess  = get_user_meta( $u->ID, 'session_tokens', true );
			$live  = 0;
			$seen  = 0;
			if ( is_array( $sess ) ) {
				foreach ( $sess as $s ) {
					if ( ! empty( $s['expiration'] ) && (int) $s['expiration'] > time() ) {
						$live++;
					}
					if ( ! empty( $s['login'] ) ) {
						$seen = max( $seen, (int) $s['login'] );
					}
				}
			}
			$apps  = class_exists( 'WP_Application_Passwords' ) ? count( (array) WP_Application_Passwords::get_user_application_passwords( $u->ID ) ) : 0;
			$user  = new WP_User( $u->ID );
			$roles = implode( ', ', (array) $user->roles );
			$out[] = array(
				'login'      => $u->user_login,
				'name'       => $u->display_name,
				'email'      => $u->user_email,
				'roles'      => $roles !== '' ? $roles : ( is_multisite() && is_super_admin( $u->ID ) ? 'super admin' : 'custom capabilities' ),
				'registered' => substr( $u->user_registered, 0, 10 ),
				'last_login' => $last ? substr( $last, 0, 10 ) : ( $seen ? gmdate( 'Y-m-d', $seen ) : 'no record' ),
				'sessions'   => $live,
				'apps'       => $apps,
				'generic'    => (bool) preg_match( '~^(?:admin|administrator|wpadmin|webmaster|test\w*|demo\w*|dev\w*|support|user\d*)$~i', $u->user_login ),
				'external'   => false,
			);
		}
		$wpdb->suppress_errors( $old );
		$site_host = preg_replace( '~^www\.~', '', strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) );
		foreach ( $out as &$a ) {
			$mail_host     = strtolower( (string) substr( strrchr( (string) $a['email'], '@' ), 1 ) );
			$a['external'] = $mail_host !== '' && $mail_host !== $site_host && substr( $mail_host, -( strlen( $site_host ) + 1 ) ) !== '.' . $site_host && substr( $site_host, -( strlen( $mail_host ) + 1 ) ) !== '.' . $mail_host;
		}
		return $out;
	}

	public static function html( $download = false ) {
		$plugins = self::plugins();
		$admins  = self::admins();
		$last    = get_option( MCSS_Scanner::OPT_LAST, array() );
		$s       = MCSS_Scanner::settings();
		$host    = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$wp_version = '';
		include ABSPATH . WPINC . '/version.php';
		$counts = array( 'blocked' => 0, 'closed' => 0, 'update' => 0, 'unknown' => 0, 'stale' => 0, 'ok' => 0 );
		foreach ( $plugins as $p ) {
			$counts[ $p['state'] ]++;
		}
		$labels = array( 'blocked' => 'Licence problem', 'closed' => 'Removed from directory', 'update' => 'Update needed', 'unknown' => 'Could not confirm', 'stale' => 'Abandoned', 'ok' => 'OK' );
		$colors = array( 'blocked' => '#b32d2e', 'closed' => '#b32d2e', 'update' => '#bd8600', 'unknown' => '#646970', 'stale' => '#bd8600', 'ok' => '#007017' );
		$hard   = array();
		foreach ( array( 'h_file_edit' => 'Code editor off', 'h_xmlrpc' => 'XML-RPC off', 'h_enum' => 'Username discovery blocked', 'h_app_pw' => 'Application passwords off', 'h_headers' => 'Security headers', 'h_uploads' => 'PHP blocked in uploads' ) as $k => $l ) {
			$hard[] = ( ! empty( $s[ $k ] ) ? '&#10003; ' : '&#9633; ' ) . $l;
		}
		ob_start();
		?>
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website status report: <?php echo esc_html( $host ); ?></title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1d2327;margin:0;padding:32px;max-width:1000px;margin:0 auto;line-height:1.5}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px;border-bottom:2px solid #dcdcde;padding-bottom:4px}
.meta{color:#646970;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid #e0e0e0}th{background:#f6f7f7;font-weight:600}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;white-space:nowrap}
.sum{display:flex;gap:18px;flex-wrap:wrap;margin:12px 0}.sum div{background:#f6f7f7;padding:10px 14px;border-radius:6px;min-width:110px}.sum b{display:block;font-size:22px}
.box{width:16px;height:16px;border:1.5px solid #8c8f94;display:inline-block;vertical-align:middle;border-radius:3px}
.note{background:#fff8e5;border-left:4px solid #dba617;padding:10px 14px;margin:12px 0;font-size:13px}
.warn{color:#b32d2e;font-weight:600}
@media print{body{padding:0}.noprint{display:none}}
</style></head><body>
<p class="noprint" style="text-align:right"><a href="#" onclick="window.print();return false;">Print or save as PDF</a></p>
<h1>Website status report</h1>
<p class="meta"><?php echo esc_html( $host ); ?> &middot; prepared <?php echo esc_html( wp_date( 'F j, Y' ) ); ?> &middot; WordPress <?php echo esc_html( $wp_version ); ?>, PHP <?php echo esc_html( PHP_VERSION ); ?></p>

<h2>Summary</h2>
<div class="sum">
	<div><b><?php echo count( $plugins ); ?></b>plugins installed</div>
	<div><b style="color:#b32d2e"><?php echo (int) ( $counts['blocked'] + $counts['closed'] ); ?></b>need a decision</div>
	<div><b style="color:#bd8600"><?php echo (int) ( $counts['update'] + $counts['stale'] ); ?></b>need an update or replacement</div>
	<div><b><?php echo count( $admins ); ?></b>administrator accounts</div>
	<?php if ( ! empty( $last['finished'] ) ) : ?><div><b><?php echo (int) $last['counts']['high']; ?></b>open high-severity findings<br><span class="meta">scan of <?php echo esc_html( wp_date( 'M j', (int) $last['finished'] ) ); ?></span></div><?php endif; ?>
</div>
<?php if ( $counts['blocked'] > 0 ) : ?>
<div class="note"><strong><?php echo (int) $counts['blocked']; ?> plugin(s) are not receiving updates because of a missing or expired licence.</strong> Out-of-date plugins are the most common way WordPress sites are broken into. Each one needs either a renewed licence or a replacement.</div>
<?php endif; ?>

<h2>Plugins</h2>
<table>
<thead><tr><th>Plugin</th><th>Installed</th><th>Latest</th><th>Status</th><th>What it means</th><th>Action needed</th></tr></thead>
<tbody>
<?php foreach ( $plugins as $p ) : ?>
<tr>
	<td><strong><?php echo esc_html( $p['name'] ); ?></strong><?php echo $p['active'] ? '' : '<br><span class="meta">inactive</span>'; ?></td>
	<td><?php echo esc_html( $p['version'] ); ?></td>
	<td><?php echo esc_html( $p['latest'] !== '' ? $p['latest'] : ( in_array( $p['state'], array( 'ok', 'stale' ), true ) ? $p['version'] : 'unknown' ) ); ?></td>
	<td><span class="pill" style="background:<?php echo esc_attr( $colors[ $p['state'] ] ); ?>"><?php echo esc_html( $labels[ $p['state'] ] ); ?></span></td>
	<td><?php echo esc_html( $p['status'] ); ?></td>
	<td><?php echo esc_html( $p['action'] ); ?></td>
</tr>
<?php endforeach; ?>
</tbody></table>
<p class="meta">Inactive plugins still need updating or removing: their code is on the server whether or not it is switched on.</p>

<h2>Administrator accounts</h2>
<p>Every account below can change anything on the website, including installing code. Please confirm each one is still needed at this level. Tick "Keep" or write the change you want.</p>
<table>
<thead><tr><th>Username</th><th>Name</th><th>Email</th><th>Role</th><th>Created</th><th>Last login</th><th>Notes</th><th>Keep?</th><th>Change to</th></tr></thead>
<tbody>
<?php foreach ( $admins as $a ) : ?>
<tr>
	<td><strong><?php echo esc_html( $a['login'] ); ?></strong></td>
	<td><?php echo esc_html( $a['name'] ); ?></td>
	<td><?php echo esc_html( $a['email'] ); ?></td>
	<td><?php echo esc_html( $a['roles'] ); ?></td>
	<td><?php echo esc_html( $a['registered'] ); ?></td>
	<td><?php echo esc_html( $a['last_login'] ); ?></td>
	<td>
		<?php if ( $a['generic'] ) : ?><span class="warn">Shared or generic username. Should be replaced with named accounts.</span><br><?php endif; ?>
		<?php if ( $a['external'] ) : ?>Outside email domain.<br><?php endif; ?>
		<?php if ( $a['apps'] ) : ?><?php echo (int) $a['apps']; ?> application password(s).<br><?php endif; ?>
		<?php if ( $a['sessions'] ) : ?><?php echo (int) $a['sessions']; ?> active login(s).<?php endif; ?>
	</td>
	<td><span class="box"></span></td>
	<td style="min-width:90px"></td>
</tr>
<?php endforeach; ?>
</tbody></table>
<p class="meta">"Last login" comes from the site's activity log and, before the log was installed, from WordPress's own session records. "No record" means the account has not signed in since logging began, which is a good reason to ask whether it is still needed.</p>

<h2>Protection in place</h2>
<p><?php echo implode( ' &nbsp;&nbsp; ', $hard ); // phpcs:ignore ?></p>
<p class="meta">Daily scan: <?php echo ! empty( $s['daily'] ) ? 'on' : 'off'; ?> &middot; instant alerts for new administrators: <?php echo ! empty( $s['alert_admins'] ) ? 'on' : 'off'; ?> &middot; hourly file watch: <?php echo ! empty( $s['alert_files'] ) ? 'on' : 'off'; ?></p>
</body></html>
		<?php
		return ob_get_clean();
	}

	public static function output() {
		if ( ! current_user_can( MCSS_Scanner::cap() ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'mcss_client_report' );
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 );
		}
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		if ( ! empty( $_GET['download'] ) ) { // phpcs:ignore
			header( 'Content-Disposition: attachment; filename="site-report-' . preg_replace( '~[^a-z0-9.-]~i', '', (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) . '-' . gmdate( 'Ymd' ) . '.html"' );
		}
		MCSS_Log::add( 'client_report', 'generated' );
		echo self::html(); // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}
}

/* =========================================================================
 * Signed updates from GitHub: plugin releases and detection rules
 * ======================================================================= */

final class MCSS_Update {

	const REPO     = 'nmarc89arelli/mc-site-scanner';
	const MANIFEST = 'https://raw.githubusercontent.com/nmarc89arelli/mc-site-scanner/main/manifest.json';
	const RULES    = 'https://raw.githubusercontent.com/nmarc89arelli/mc-site-scanner/main/rules.dat';
	const SLUG     = 'mc-site-scanner';

	public static function hooks() {
		add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'inject_update' ) );
		add_filter( 'plugins_api', array( __CLASS__, 'plugin_info' ), 20, 3 );
		add_filter( 'upgrader_pre_download', array( __CLASS__, 'verified_download' ), 10, 3 );
		add_filter( 'auto_update_plugin', array( __CLASS__, 'auto_update' ), 10, 2 );
		add_filter( 'plugin_row_meta', array( __CLASS__, 'row_meta' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'after_update' ), 10, 2 );
	}

	public static function available() {
		return defined( 'MCSS_PUBKEY' ) && strlen( (string) base64_decode( MCSS_PUBKEY, true ) ) === 32 && function_exists( 'sodium_crypto_sign_verify_detached' );
	}

	/** True only when $sig is a valid Ed25519 signature of $data by the key baked into this plugin. */
	public static function verify( $data, $sig ) {
		if ( ! self::available() || ! is_string( $data ) || ! is_string( $sig ) || strlen( $sig ) !== 64 ) {
			return false;
		}
		try {
			return sodium_crypto_sign_verify_detached( $sig, $data, base64_decode( MCSS_PUBKEY, true ) );
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	private static function fetch( $url, $timeout = 10 ) {
		$r = wp_remote_get( $url, array( 'timeout' => $timeout, 'user-agent' => 'RelishSecurity/' . MCSS_Scanner::VERSION, 'headers' => array( 'Cache-Control' => 'no-cache' ) ) );
		if ( is_wp_error( $r ) || (int) wp_remote_retrieve_response_code( $r ) !== 200 ) {
			return null;
		}
		return (string) wp_remote_retrieve_body( $r );
	}

	/** Signed manifest, cached for six hours. Returns null when missing or when the signature fails. */
	public static function manifest( $force = false ) {
		if ( ! self::available() ) {
			return null;
		}
		$cached = get_site_transient( 'mcss_manifest' );
		if ( ! $force && is_array( $cached ) ) {
			return empty( $cached['none'] ) ? $cached : null;
		}
		$json = self::fetch( self::MANIFEST );
		$sig  = self::fetch( self::MANIFEST . '.sig' );
		$m    = null;
		if ( $json !== null && $sig !== null && self::verify( $json, $sig ) ) {
			$m = json_decode( $json, true );
			if ( ! is_array( $m ) || empty( $m['version'] ) || empty( $m['download_url'] ) || ! preg_match( '~^https://github\.com/' . preg_quote( self::REPO, '~' ) . '/releases/download/~', $m['download_url'] ) ) {
				$m = null;
			}
		} elseif ( $json !== null && $sig !== null ) {
			MCSS_Log::add( 'update_rejected', 'manifest', 'signature did not verify' );
		}
		set_site_transient( 'mcss_manifest', $m ? $m : array( 'none' => 1 ), 6 * HOUR_IN_SECONDS );
		update_site_option( 'mcss_update_checked', time() );
		return $m;
	}

	public static function inject_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}
		$m    = self::manifest();
		$file = plugin_basename( MCSS_FILE );
		if ( $m && version_compare( $m['version'], MCSS_Scanner::VERSION, '>' ) ) {
			$item = (object) array(
				'id'            => 'github.com/' . self::REPO,
				'slug'          => self::SLUG,
				'plugin'        => $file,
				'new_version'   => (string) $m['version'],
				'url'           => 'https://github.com/' . self::REPO,
				'package'       => (string) $m['download_url'],
				'icons'         => array(),
				'banners'       => array(),
				'tested'        => isset( $m['tested'] ) ? (string) $m['tested'] : '',
				'requires_php'  => isset( $m['requires_php'] ) ? (string) $m['requires_php'] : '7.4',
				'compatibility' => new stdClass(),
			);
			$transient->response[ $file ] = $item;
			unset( $transient->no_update[ $file ] );
		} else {
			$transient->no_update[ $file ] = (object) array( 'id' => 'github.com/' . self::REPO, 'slug' => self::SLUG, 'plugin' => $file, 'new_version' => MCSS_Scanner::VERSION, 'url' => 'https://github.com/' . self::REPO, 'package' => '' );
			unset( $transient->response[ $file ] );
		}
		return $transient;
	}

	public static function plugin_info( $result, $action, $args ) {
		if ( $action !== 'plugin_information' || empty( $args->slug ) || $args->slug !== self::SLUG ) {
			return $result;
		}
		$m = self::manifest();
		if ( ! $m ) {
			return $result;
		}
		return (object) array(
			'name'          => 'Relish Security',
			'slug'          => self::SLUG,
			'version'       => (string) $m['version'],
			'author'        => 'Marcarelli Consulting',
			'homepage'      => 'https://github.com/' . self::REPO,
			'download_link' => (string) $m['download_url'],
			'requires'      => isset( $m['requires'] ) ? (string) $m['requires'] : '5.8',
			'tested'        => isset( $m['tested'] ) ? (string) $m['tested'] : '',
			'requires_php'  => isset( $m['requires_php'] ) ? (string) $m['requires_php'] : '7.4',
			'last_updated'  => isset( $m['released'] ) ? (string) $m['released'] : '',
			'sections'      => array( 'description' => 'Malware and integrity scanner with incident response tools.', 'changelog' => isset( $m['changelog'] ) ? '<p>' . nl2br( esc_html( (string) $m['changelog'] ) ) . '</p>' : '' ),
		);
	}

	/** Download the release zip ourselves and refuse it unless its detached signature verifies. */
	public static function verified_download( $reply, $package, $upgrader ) {
		if ( ! is_string( $package ) || strpos( $package, 'https://github.com/' . self::REPO . '/releases/download/' ) !== 0 ) {
			return $reply;
		}
		if ( ! self::available() ) {
			return new WP_Error( 'mcss_nosign', 'This site cannot verify update signatures (sodium missing), so the scanner will not install updates from the network. Update it by uploading the zip.' );
		}
		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$tmp = download_url( $package, 120 );
		if ( is_wp_error( $tmp ) ) {
			return $tmp;
		}
		$sig = self::fetch( $package . '.sig', 20 );
		if ( $sig === null || ! self::verify( (string) file_get_contents( $tmp ), $sig ) ) {
			@unlink( $tmp );
			MCSS_Log::add( 'update_rejected', basename( $package ), 'signature missing or did not verify' );
			MCSS_Alerts::send( 'update_rejected', 'A scanner update was refused: signature did not verify', array( 'Package: ' . $package, 'Either the release was not signed with your key, or something between GitHub and this site altered it. No change was made.' ), true );
			return new WP_Error( 'mcss_badsig', 'The update package failed signature verification and was not installed.' );
		}
		MCSS_Log::add( 'update_verified', basename( $package ) );
		return $tmp;
	}

	public static function auto_update( $update, $item ) {
		if ( is_object( $item ) && isset( $item->plugin ) && $item->plugin === plugin_basename( MCSS_FILE ) ) {
			$s = MCSS_Scanner::settings();
			return ! empty( $s['auto_update'] );
		}
		return $update;
	}

	public static function after_update( $upgrader, $extra ) {
		if ( is_array( $extra ) && isset( $extra['type'] ) && $extra['type'] === 'plugin' ) {
			delete_site_transient( 'mcss_manifest' );
			MCSS_Alerts::watch( true );
		}
	}

	public static function row_meta( $links, $file ) {
		if ( $file === plugin_basename( MCSS_FILE ) ) {
			$links[] = self::available() ? 'Signed updates from GitHub' : '<span style="color:#b32d2e">Update signing unavailable on this host</span>';
		}
		return $links;
	}

	/** Detection rules: fetched daily, replaced only when the signature verifies and the file parses. */
	public static function update_rules() {
		if ( ! self::available() ) {
			return 'unavailable';
		}
		$path = MCSS_Scanner::rules_file();
		$data = self::fetch( self::RULES, 15 );
		$sig  = self::fetch( self::RULES . '.sig', 10 );
		if ( $data === null || $sig === null ) {
			return 'unreachable';
		}
		if ( ! self::verify( $data, $sig ) ) {
			MCSS_Log::add( 'update_rejected', 'rules.dat', 'signature did not verify' );
			return 'badsig';
		}
		if ( is_file( $path ) && hash( 'sha256', $data ) === (string) @hash_file( 'sha256', $path ) ) {
			update_site_option( 'mcss_rules_checked', time() );
			return 'current';
		}
		$parsed = json_decode( str_rot13( $data ), true );
		if ( ! is_array( $parsed ) || empty( $parsed['php'] ) || empty( $parsed['named'] ) ) {
			MCSS_Log::add( 'update_rejected', 'rules.dat', 'verified but did not parse' );
			return 'badfile';
		}
		if ( ! is_writable( dirname( $path ) ) ) {
			return 'readonly';
		}
		$tmp = $path . '.' . strtolower( wp_generate_password( 8, false ) ) . '.tmp';
		if ( @file_put_contents( $tmp, $data, LOCK_EX ) !== strlen( $data ) || ! @rename( $tmp, $path ) ) {
			@unlink( $tmp );
			return 'writefail';
		}
		update_site_option( 'mcss_rules_checked', time() );
		update_site_option( 'mcss_rules_updated', time() );
		MCSS_Log::add( 'rules_updated', 'rules.dat', 'sha256 ' . substr( hash( 'sha256', $data ), 0, 16 ) . ', ' . count( $parsed['php'] ) . ' php rules' );
		MCSS_Alerts::watch( true );
		return 'updated';
	}

	public static function maybe_update_rules() {
		if ( (int) get_site_option( 'mcss_rules_checked', 0 ) > time() - DAY_IN_SECONDS + 300 ) {
			return;
		}
		self::update_rules();
	}

	public static function status() {
		$m = self::manifest();
		return array(
			'signing'        => self::available(),
			'latest'         => $m ? (string) $m['version'] : '',
			'checked'        => (int) get_site_option( 'mcss_update_checked', 0 ),
			'rules_checked'  => (int) get_site_option( 'mcss_rules_checked', 0 ),
			'rules_updated'  => (int) get_site_option( 'mcss_rules_updated', 0 ),
			'rules_sha'      => substr( (string) @hash_file( 'sha256', MCSS_Scanner::rules_file() ), 0, 12 ),
		);
	}
}

/* =========================================================================
 * Admin screens
 * ======================================================================= */

final class MCSS_Admin {

	public static function hooks() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( 'MCSS_Log', 'maybe_install' ) );
		add_action( 'admin_post_mcss_save', array( __CLASS__, 'save_settings' ) );
		add_action( 'admin_post_mcss_save_hardening', array( __CLASS__, 'save_hardening' ) );
		add_action( 'admin_post_mcss_log_csv', array( __CLASS__, 'log_csv' ) );
		add_action( 'admin_post_mcss_client_report', array( 'MCSS_Report', 'output' ) );
		add_action( 'wp_ajax_mcss_quarantine', array( __CLASS__, 'ajax_quarantine' ) );
		add_action( 'wp_ajax_mcss_fix', array( __CLASS__, 'ajax_fix' ) );
		add_action( 'wp_ajax_mcss_repair', array( __CLASS__, 'ajax_repair' ) );
		add_action( 'wp_ajax_mcss_restore', array( __CLASS__, 'ajax_restore' ) );
		add_action( 'wp_ajax_mcss_purge', array( __CLASS__, 'ajax_purge' ) );
		add_action( 'wp_ajax_mcss_test_webhook', array( __CLASS__, 'ajax_test_webhook' ) );
		add_action( 'wp_ajax_mcss_check_updates', array( __CLASS__, 'ajax_check_updates' ) );
	}

	public static function activate() {
		MCSS_Log::maybe_install();
		register_uninstall_hook( MCSS_FILE, array( 'MCSS_Scanner', 'uninstall' ) );
		// Pin the alert address now. Left to follow the site admin email, an attacker who changes that email would receive the alert about it.
		$s = get_option( MCSS_Scanner::OPT_SETTINGS, array() );
		// Always re-save: this also flips the option to autoload on sites upgraded from an older version.
		self::merge_settings( ( ! is_array( $s ) || empty( $s['email'] ) ) ? array( 'email' => (string) get_option( 'admin_email' ) ) : array() );
		MCSS_Alerts::ensure_cron();
		MCSS_Alerts::watch( true );
	}

	public static function menu() {
		add_management_page( 'Relish Security', 'Relish Security', MCSS_Scanner::cap(), 'mcss', array( __CLASS__, 'page' ) );
	}

	private static function reply( $r ) {
		$r['ok'] ? wp_send_json_success( $r ) : wp_send_json_error( $r );
	}

	private static function posted_key( $name, $len ) {
		$v = isset( $_POST[ $name ] ) ? preg_replace( '~[^a-z0-9]~', '', (string) wp_unslash( $_POST[ $name ] ) ) : '';
		return strlen( $v ) === $len ? $v : '';
	}

	public static function ajax_fix() {
		MCSS_Scanner::guard_action();
		$kind = isset( $_POST['kind'] ) ? preg_replace( '~[^a-z_]~', '', (string) wp_unslash( $_POST['kind'] ) ) : '';
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 );
		}
		self::reply( MCSS_Repair::fix( $kind, self::posted_key( 'k', 32 ) ) );
	}

	public static function ajax_quarantine() {
		MCSS_Scanner::guard_action();
		self::reply( MCSS_Repair::quarantine( self::posted_key( 'k', 32 ) ) );
	}

	public static function ajax_repair() {
		MCSS_Scanner::guard_action();
		self::reply( MCSS_Repair::repair( self::posted_key( 'k', 32 ) ) );
	}

	public static function ajax_restore() {
		MCSS_Scanner::guard_action();
		self::reply( MCSS_Repair::restore( self::posted_key( 'id', 16 ) ) );
	}

	public static function ajax_purge() {
		MCSS_Scanner::guard_action();
		self::reply( MCSS_Repair::purge( self::posted_key( 'id', 16 ) ) );
	}

	public static function ajax_check_updates() {
		MCSS_Scanner::guard_action();
		delete_site_transient( 'mcss_manifest' );
		$m = MCSS_Update::manifest( true );
		update_site_option( 'mcss_rules_checked', 0 );
		$r = MCSS_Update::update_rules();
		delete_site_transient( 'update_plugins' );
		wp_update_plugins();
		$words = array( 'updated' => 'new rules installed', 'current' => 'rules already current', 'unreachable' => 'GitHub could not be reached for rules', 'badsig' => 'rules REFUSED, signature did not verify', 'badfile' => 'rules refused, file did not parse', 'readonly' => 'rules could not be written (folder not writable)', 'writefail' => 'rules could not be written', 'unavailable' => 'signature checking unavailable on this host' );
		$msg = ( $m ? 'Latest release is ' . $m['version'] . ( version_compare( $m['version'], MCSS_Scanner::VERSION, '>' ) ? ' and it now shows on the Updates screen.' : ', which is what is installed.' ) : 'No signed release manifest could be read from GitHub.' ) . ' Rules: ' . ( isset( $words[ $r ] ) ? $words[ $r ] : $r ) . '.';
		self::reply( array( 'ok' => (bool) $m, 'message' => $msg ) );
	}

	public static function ajax_test_webhook() {
		MCSS_Scanner::guard_action();
		$s = MCSS_Scanner::settings();
		if ( empty( $s['webhook'] ) ) {
			self::reply( array( 'ok' => false, 'message' => 'Save a webhook URL first.' ) );
		}
		MCSS_Alerts::webhook( 'alert', array( 'alert' => 'test', 'subject' => 'Test message from Relish Security', 'lines' => array( 'If you can read this, reporting works.' ) ), true );
		self::reply( array( 'ok' => true, 'message' => 'Test sent. Check the receiving end.' ) );
	}

	private static function merge_settings( $changes ) {
		$s = get_option( MCSS_Scanner::OPT_SETTINGS, array() );
		$s = is_array( $s ) ? $s : array();
		// Autoloaded on purpose: the hardening switches read this on every request, and autoload makes that free.
		update_option( MCSS_Scanner::OPT_SETTINGS, array_merge( $s, $changes ), true );
		if ( function_exists( 'wp_set_option_autoload' ) ) {
			wp_set_option_autoload( MCSS_Scanner::OPT_SETTINGS, true );
		}
	}

	public static function save_settings() {
		if ( ! current_user_can( MCSS_Scanner::cap() ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'mcss_save' );
		$webhook = isset( $_POST['webhook'] ) ? esc_url_raw( trim( (string) wp_unslash( $_POST['webhook'] ) ), array( 'https' ) ) : '';
		$urls    = isset( $_POST['render_urls'] ) ? sanitize_textarea_field( wp_unslash( $_POST['render_urls'] ) ) : '';
		$changes = array(
			'daily'         => empty( $_POST['daily'] ) ? 0 : 1,
			'email'         => isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '',
			'alert_admins'  => empty( $_POST['alert_admins'] ) ? 0 : 1,
			'alert_plugins' => empty( $_POST['alert_plugins'] ) ? 0 : 1,
			'alert_files'   => empty( $_POST['alert_files'] ) ? 0 : 1,
			'render'        => empty( $_POST['render'] ) ? 0 : 1,
			'render_urls'   => substr( $urls, 0, 2000 ),
			'vuln'          => empty( $_POST['vuln'] ) ? 0 : 1,
			'webhook'       => $webhook,
			'secret'        => isset( $_POST['secret'] ) ? substr( sanitize_text_field( wp_unslash( $_POST['secret'] ) ), 0, 128 ) : '',
			'log_days'      => isset( $_POST['log_days'] ) ? max( 7, min( 730, (int) $_POST['log_days'] ) ) : 90,
			'auto_update'   => empty( $_POST['auto_update'] ) ? 0 : 1,
		);
		// Anything that makes the site quieter is announced to the OLD recipients before it takes effect.
		$old  = MCSS_Scanner::settings();
		$diff = array();
		foreach ( array( 'alert_admins' => 'Account alerts', 'alert_plugins' => 'Plugin alerts', 'alert_files' => 'Critical file watch', 'daily' => 'Daily scan' ) as $k => $label ) {
			if ( ! empty( $old[ $k ] ) && empty( $changes[ $k ] ) ) {
				$diff[] = $label . ' switched OFF';
			}
		}
		if ( (string) $old['email'] !== (string) $changes['email'] ) {
			$diff[] = 'Alert email changed: ' . $old['email'] . ' -> ' . ( $changes['email'] !== '' ? $changes['email'] : '(none)' );
		}
		if ( (string) $old['webhook'] !== (string) $changes['webhook'] ) {
			$diff[] = 'Webhook ' . ( $changes['webhook'] === '' ? 'removed' : 'changed' );
		}
		if ( ! empty( $diff ) ) {
			$diff[] = '';
			$diff[] = 'Done by: ' . MCSS_Scanner::current_login() . ' from ' . MCSS_Log::ip();
			$diff[] = 'If this was not you, someone with an administrator login is turning the alarms down.';
			MCSS_Alerts::send( 'alerting_reduced', 'Scanner alert settings were changed', $diff, true );
		}
		self::merge_settings( $changes );
		MCSS_Alerts::ensure_cron();
		MCSS_Log::add( 'settings_saved', 'scanner settings', implode( '; ', array_filter( $diff ) ) );
		wp_safe_redirect( admin_url( 'tools.php?page=mcss&tab=settings&saved=1' ) );
		exit;
	}

	public static function save_hardening() {
		if ( ! current_user_can( MCSS_Scanner::cap() ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'mcss_save_hardening' );
		$old     = MCSS_Scanner::settings();
		$changes = array();
		foreach ( array( 'h_file_edit', 'h_xmlrpc', 'h_enum', 'h_app_pw', 'h_version', 'h_headers', 'h_uploads' ) as $k ) {
			$changes[ $k ] = empty( $_POST[ $k ] ) ? 0 : 1;
		}
		$msg = '';
		if ( $changes['h_uploads'] !== (int) $old['h_uploads'] ) {
			$r = MCSS_Harden::uploads_rule( (bool) $changes['h_uploads'] );
			if ( $r !== true ) {
				$changes['h_uploads'] = (int) $old['h_uploads'];
				$msg                  = $r;
			}
		}
		self::merge_settings( $changes );
		$on = array();
		foreach ( $changes as $k => $v ) {
			if ( $v ) {
				$on[] = substr( $k, 2 );
			}
		}
		MCSS_Log::add( 'hardening_changed', '', 'on: ' . ( $on ? implode( ', ', $on ) : 'none' ) );
		set_transient( 'mcss_notice_' . get_current_user_id(), $msg, 60 );
		wp_safe_redirect( admin_url( 'tools.php?page=mcss&tab=hardening&saved=1' ) );
		exit;
	}

	public static function log_csv() {
		if ( ! current_user_can( MCSS_Scanner::cap() ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'mcss_log_csv' );
		$res = MCSS_Log::query( '', '', 1, 5000 );
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="activity-log-' . gmdate( 'Ymd-Hi' ) . '.csv"' );
		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, array( 'time_utc', 'user', 'ip', 'event', 'object', 'detail' ), ',', '"', '\\' );
		foreach ( $res['rows'] as $r ) {
			$row = array( $r->created, $r->user_login, $r->ip, $r->event, $r->object, $r->detail );
			foreach ( $row as $i => $cell ) {
				if ( $cell !== '' && strpos( "=+-@\t\r", $cell[0] ) !== false ) {
					$row[ $i ] = "'" . $cell;
				}
			}
			fputcsv( $out, $row, ',', '"', '\\' );
		}
		fclose( $out );
		exit;
	}

	/* ---------------------------------------------------------------------
	 * Page
	 * ------------------------------------------------------------------- */

	public static function page() {
		if ( ! current_user_can( MCSS_Scanner::cap() ) ) {
			return;
		}
		$tabs = array( 'scan' => 'Scan', 'report' => 'Client report', 'activity' => 'Activity log', 'response' => 'Response', 'hardening' => 'Hardening', 'settings' => 'Settings' );
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'scan'; // phpcs:ignore
		if ( ! isset( $tabs[ $tab ] ) ) {
			$tab = 'scan';
		}
		$state   = MCSS_Scanner::state();
		$running = ! empty( $state ) && empty( $state['done'] ) && ( time() - (int) $state['updated'] ) < 600;
		?>
		<div class="wrap mcss">
			<h1>Relish Security</h1>
			<style>
				.mcss .card{max-width:none;padding:16px 20px;margin-top:16px}
				.mcss .bar{height:10px;background:#dcdcde;border-radius:5px;overflow:hidden;margin:10px 0;max-width:600px}
				.mcss .bar i{display:block;height:100%;width:0;background:#2271b1;transition:width .3s}
				.mcss .sev{display:inline-block;padding:2px 8px;border-radius:3px;color:#fff;font-size:11px;font-weight:600;text-transform:uppercase}
				.mcss .sev.high{background:#b32d2e}.mcss .sev.medium{background:#bd8600}.mcss .sev.low{background:#646970}
				.mcss td code{font-size:12px;word-break:break-all;background:none;padding:0}
				.mcss .snip{display:block;margin-top:4px;color:#50575e;font-family:Consolas,Monaco,monospace;font-size:11px;word-break:break-all}
				.mcss .tally span{margin-right:18px;font-size:14px}
				.mcss table.widefat td{vertical-align:top}
				.mcss details{margin-top:12px}.mcss summary{cursor:pointer;font-weight:600}
				.mcss .acts a{display:block;white-space:nowrap}
				.mcss .acts a.mcss-fix{font-weight:600}
				.mcss #mcss-act-msg{font-weight:600;position:sticky;bottom:0;background:#f0f0f1;padding:8px 0;margin:0}
			</style>
			<nav class="nav-tab-wrapper">
				<?php foreach ( $tabs as $k => $label ) : ?>
					<a class="nav-tab <?php echo $k === $tab ? 'nav-tab-active' : ''; ?>" href="<?php echo esc_url( admin_url( 'tools.php?page=mcss&tab=' . $k ) ); ?>"><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</nav>
			<?php
			call_user_func( array( __CLASS__, 'tab_' . $tab ), $running );
			?>
			<p id="mcss-act-msg"></p>
		</div>
		<?php
		self::script( $running );
	}

	private static function tab_scan( $running ) {
		$last     = get_option( MCSS_Scanner::OPT_LAST, array() );
		$findings = MCSS_Scanner::visible_findings();
		$ignored  = count( MCSS_Scanner::ignored() );
		$inv      = ! empty( $last['inventory'] ) ? $last['inventory'] : array();
		$sev_name = array( 'high' => 'High', 'medium' => 'Medium', 'low' => 'Low' );
		?>
		<div class="card">
			<?php if ( ! empty( $last['finished'] ) ) : ?>
				<p class="tally">
					<span><strong><?php echo (int) $last['counts']['high']; ?></strong> high</span>
					<span><strong><?php echo (int) $last['counts']['medium']; ?></strong> medium</span>
					<span><strong><?php echo (int) $last['counts']['low']; ?></strong> low</span>
				</p>
				<p>Last scan finished <?php echo esc_html( wp_date( 'M j, Y g:i a', (int) $last['finished'] ) ); ?>. <?php echo esc_html( number_format( (int) $last['files'] ) ); ?> unverified files pattern-scanned in <?php echo (int) $last['duration']; ?> seconds (<?php echo esc_html( $last['mode'] ); ?>).</p>
			<?php else : ?>
				<p>No scan has been run yet.</p>
			<?php endif; ?>
			<p>
				<button class="button button-primary" id="mcss-run"><?php echo $running ? 'Resume scan' : 'Run scan'; ?></button>
				<?php if ( ! empty( $last['finished'] ) ) : ?>
					<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=mcss_report' ), 'mcss_report' ) ); ?>">Download report</a>
				<?php endif; ?>
			</p>
			<div id="mcss-progress" style="display:none"><div class="bar"><i></i></div><p id="mcss-label"></p></div>
			<p class="description">Scanning only reads. Work is done in 6 second batches, so you can leave this page and resume later.</p>
		</div>

		<?php if ( ! empty( $last['notes'] ) ) : ?>
			<div class="card"><?php foreach ( $last['notes'] as $n ) : ?><p><?php echo esc_html( $n ); ?></p><?php endforeach; ?></div>
		<?php endif; ?>

		<?php if ( empty( $last['finished'] ) ) { return; } ?>

		<div class="card">
			<h2>Findings</h2>
			<?php if ( empty( $findings ) ) : ?>
				<p>Nothing to review.</p>
			<?php else : ?>
			<table class="widefat striped">
				<thead><tr><th style="width:80px">Severity</th><th>Finding</th><th style="width:130px">File modified</th><th style="width:160px">Fix</th></tr></thead>
				<tbody>
				<?php $shown = 0; ?>
				<?php foreach ( $findings as $f ) : ?>
					<?php
					if ( ++$shown > 400 ) {
						break;
					}
					$acts = MCSS_Repair::actions_for( $f );
					?>
					<tr>
						<td><span class="sev <?php echo esc_attr( $f['sev'] ); ?>"><?php echo esc_html( isset( $sev_name[ $f['sev'] ] ) ? $sev_name[ $f['sev'] ] : $f['sev'] ); ?></span></td>
						<td>
							<strong><?php echo esc_html( $f['title'] ); ?></strong>
							<?php if ( $f['path'] !== '' ) : ?><br><code><?php echo esc_html( $f['path'] . ( $f['line'] ? ':' . $f['line'] : '' ) ); ?></code><?php endif; ?>
							<?php if ( $f['snip'] !== '' ) : ?><span class="snip"><?php echo esc_html( $f['snip'] ); ?></span><?php endif; ?>
							<?php if ( $f['note'] !== '' ) : ?><br><em><?php echo esc_html( $f['note'] ); ?></em><?php endif; ?>
						</td>
						<td><?php echo $f['mt'] ? esc_html( wp_date( 'M j, Y H:i', (int) $f['mt'] ) ) : ''; ?></td>
						<td class="acts">
							<?php foreach ( $acts as $a ) : ?>
								<?php if ( isset( $a['href'] ) ) : ?>
									<a href="<?php echo esc_url( $a['href'] ); ?>"><?php echo esc_html( $a['label'] ); ?></a>
								<?php else : ?>
									<a href="#" class="mcss-act mcss-fix" data-action="mcss_fix" data-kind="<?php echo esc_attr( $a['kind'] ); ?>" data-k="<?php echo esc_attr( $a['k'] ); ?>" <?php echo $a['kind'] === 'trace_option' ? '' : 'data-hide="1"'; ?> <?php echo $a['kind'] === 'rotate_salts' ? 'data-logout="1"' : ''; ?> data-confirm="<?php echo esc_attr( $a['confirm'] ); ?>"><?php echo esc_html( $a['label'] ); ?></a>
								<?php endif; ?>
							<?php endforeach; ?>
							<a href="#" class="mcss-ignore" data-k="<?php echo esc_attr( $f['k'] ); ?>">Ignore</a>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php if ( count( $findings ) > 400 ) : ?>
				<p><strong>Showing the 400 most severe of <?php echo (int) count( $findings ); ?> findings.</strong> Download the report for the full list, or deal with these and scan again.</p>
			<?php endif; ?>
			<p class="description">High means act now. Medium and low are things malware does that legitimate code sometimes does too, so read them first. Every fix in the last column is reversible or verified: files and plugins go to quarantine rather than being deleted, the site is health-checked after each change and rolled back if it stops responding, and accounts are downgraded rather than removed. A finding with no fix listed needs a human decision. Ignore hides a finding until that file changes.</p>
			<?php endif; ?>
			<?php if ( $ignored ) : ?>
				<p><?php echo (int) $ignored; ?> ignored. <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=mcss_reset_ignored' ), 'mcss_reset_ignored' ) ); ?>">Show them again</a></p>
			<?php endif; ?>
		</div>

		<div class="card">
			<h2>Inventory</h2>
			<p class="description">Places malware likes to live and things it likes to create. Read the lists and make sure you recognise every line.</p>
			<details open><summary>Must-use plugins and drop-ins</summary>
				<table class="widefat striped"><thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead><tbody>
				<?php foreach ( array_merge( isset( $inv['mu'] ) ? $inv['mu'] : array(), isset( $inv['dropins'] ) ? $inv['dropins'] : array() ) as $m ) : ?>
					<tr><td><code><?php echo esc_html( $m['path'] ); ?></code></td><td><?php echo esc_html( size_format( $m['size'] ) ); ?></td><td><?php echo esc_html( wp_date( 'M j, Y H:i', (int) $m['mt'] ) ); ?></td></tr>
				<?php endforeach; ?>
				</tbody></table>
			</details>
			<details><summary>Administrators (<?php echo isset( $inv['admins'] ) ? count( $inv['admins'] ) : 0; ?>)</summary>
				<table class="widefat striped"><thead><tr><th>Login</th><th>Email</th><th>Registered</th><th>Active session IPs</th><th>Application passwords</th></tr></thead><tbody>
				<?php foreach ( ( isset( $inv['admins'] ) ? $inv['admins'] : array() ) as $a ) : ?>
					<tr><td><?php echo esc_html( $a['login'] ); ?></td><td><?php echo esc_html( $a['email'] ); ?></td><td><?php echo esc_html( $a['registered'] ); ?></td>
					<td><?php foreach ( $a['ips'] as $ip => $t ) { echo esc_html( $ip . ( $t ? ' (' . wp_date( 'M j', $t ) . ')' : '' ) ) . '<br>'; } ?></td>
					<td><?php foreach ( ( isset( $a['apps'] ) ? $a['apps'] : array() ) as $ap ) { echo esc_html( $ap ) . '<br>'; } ?></td></tr>
				<?php endforeach; ?>
				</tbody></table>
			</details>
			<details><summary>External script domains</summary>
				<table class="widefat striped"><thead><tr><th>Domain</th><th>Where</th><th>Known service</th></tr></thead><tbody>
				<?php foreach ( ( isset( $inv['domains'] ) ? $inv['domains'] : array() ) as $d => $info ) : ?>
					<tr><td><?php echo esc_html( $d ); ?></td><td>Database: <?php echo esc_html( implode( ', ', $info['where'] ) ); ?></td><td><?php echo ! empty( $info['trusted'] ) ? 'Yes' : 'No'; ?></td></tr>
				<?php endforeach; ?>
				<?php $tr = MCSS_Scanner::trusted_domains(); ?>
				<?php foreach ( ( isset( $inv['page_domains'] ) ? $inv['page_domains'] : array() ) as $d ) : ?>
					<tr><td><?php echo esc_html( $d ); ?></td><td>Live page</td><td><?php echo MCSS_Scanner::is_trusted( $d, $tr ) ? 'Yes' : 'No'; ?></td></tr>
				<?php endforeach; ?>
				</tbody></table>
			</details>
			<details><summary>Plugin verification</summary>
				<table class="widefat striped"><thead><tr><th>Plugin</th><th>Result</th></tr></thead><tbody>
				<?php
				$labels = array(
					'verified'     => 'Matches the official wordpress.org release',
					'unverifiable' => 'Not on wordpress.org (premium or custom). Pattern-scanned only',
					'differs'      => 'Same slug as a wordpress.org plugin but different code. Pattern-scanned only',
				);
				foreach ( ( isset( $inv['plugins'] ) ? $inv['plugins'] : array() ) as $slug => $st ) :
					?>
					<tr><td><?php echo esc_html( $slug ); ?></td><td><?php echo esc_html( isset( $labels[ $st ] ) ? $labels[ $st ] : $st ); ?></td></tr>
				<?php endforeach; ?>
				</tbody></table>
			</details>
		</div>
		<?php
	}

	private static function tab_activity( $running ) {
		$event  = isset( $_GET['event'] ) ? sanitize_key( $_GET['event'] ) : ''; // phpcs:ignore
		$search = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : ''; // phpcs:ignore
		$paged  = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1; // phpcs:ignore
		$res    = MCSS_Log::query( $event, $search, $paged, 50 );
		$pages  = (int) ceil( $res['total'] / 50 );
		$base   = admin_url( 'tools.php?page=mcss&tab=activity' . ( $event !== '' ? '&event=' . rawurlencode( $event ) : '' ) . ( $search !== '' ? '&s=' . rawurlencode( $search ) : '' ) );
		?>
		<div class="card">
			<form method="get" action="<?php echo esc_url( admin_url( 'tools.php' ) ); ?>">
				<input type="hidden" name="page" value="mcss"><input type="hidden" name="tab" value="activity">
				<select name="event">
					<option value="">All events</option>
					<?php foreach ( MCSS_Log::events() as $e ) : ?>
						<option value="<?php echo esc_attr( $e ); ?>" <?php selected( $event, $e ); ?>><?php echo esc_html( str_replace( '_', ' ', $e ) ); ?></option>
					<?php endforeach; ?>
				</select>
				<input type="search" name="s" value="<?php echo esc_attr( $search ); ?>" placeholder="User, IP or object">
				<button class="button">Filter</button>
				<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=mcss_log_csv' ), 'mcss_log_csv' ) ); ?>">Export CSV</a>
			</form>
			<p class="description"><?php echo esc_html( number_format( $res['total'] ) ); ?> entries. Times are UTC. Logins, failed logins, user and role changes, plugin and theme changes, file editor use, key settings, alerts and everything this plugin does. The IP is the address the server saw. Forwarded headers are recorded too but can be faked by the visitor.</p>
			<table class="widefat striped">
				<thead><tr><th style="width:140px">Time</th><th>User</th><th>IP</th><th>Event</th><th>Object</th><th>Detail</th></tr></thead>
				<tbody>
				<?php if ( empty( $res['rows'] ) ) : ?>
					<tr><td colspan="6">Nothing logged yet.</td></tr>
				<?php endif; ?>
				<?php foreach ( $res['rows'] as $r ) : ?>
					<tr>
						<td><?php echo esc_html( $r->created ); ?></td>
						<td><?php echo esc_html( $r->user_login ); ?></td>
						<td><?php echo esc_html( $r->ip ); ?></td>
						<td><?php echo esc_html( str_replace( '_', ' ', $r->event ) ); ?></td>
						<td><code><?php echo esc_html( $r->object ); ?></code></td>
						<td><?php echo esc_html( $r->detail ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php if ( $pages > 1 ) : ?>
				<p>
					<?php if ( $paged > 1 ) : ?><a class="button" href="<?php echo esc_url( $base . '&paged=' . ( $paged - 1 ) ); ?>">Newer</a><?php endif; ?>
					Page <?php echo (int) $paged; ?> of <?php echo (int) $pages; ?>
					<?php if ( $paged < $pages ) : ?><a class="button" href="<?php echo esc_url( $base . '&paged=' . ( $paged + 1 ) ); ?>">Older</a><?php endif; ?>
				</p>
			<?php endif; ?>
		</div>
		<?php
	}

	private static function tab_response( $running ) {
		$cfg      = MCSS_Scanner::config_path();
		$rotated  = get_option( MCSS_Scanner::OPT_SALTS, array() );
		$writable = $cfg !== '' && is_writable( $cfg );
		$items    = MCSS_Repair::items();
		?>
		<div class="card">
			<h2>Incident response</h2>
			<p class="description">Remove the malware first. If a backdoor is still on the site, the attacker walks straight back in after any of these.</p>
			<table class="form-table" role="presentation"><tbody>
				<tr>
					<th scope="row">Rotate salts</th>
					<td>
						<p><button class="button mcss-act" data-action="mcss_rotate_salts" data-logout="1" data-confirm="Replace all 8 keys and salts in wp-config.php? Every user is logged out immediately, including you.">Rotate salts now</button></p>
						<p class="description">Ends every login session, including any the attacker holds. A backup of wp-config.php is written first, the new file is checked as valid PHP before it goes live, the swap is atomic, and the original is restored automatically if the read-back does not match. If any check fails, nothing is touched.</p>
						<p class="description">
							wp-config.php: <code><?php echo esc_html( $cfg !== '' ? $cfg : 'not found' ); ?></code> (<?php echo $writable ? 'writable' : 'not writable by PHP, rotate over SFTP or WP-CLI instead'; ?>).
							<?php if ( ! empty( $rotated['time'] ) ) : ?>
								Last rotated here <?php echo esc_html( wp_date( 'M j, Y g:i a', (int) $rotated['time'] ) ); ?> by <?php echo esc_html( $rotated['user'] ); ?>.
							<?php else : ?>
								Never rotated from this plugin.
							<?php endif; ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row">Reset administrator passwords</th>
					<td>
						<p><button class="button mcss-act" data-action="mcss_reset_admins" data-confirm="Give every other administrator a new random password, revoke their application passwords and email each of them a reset link?">Reset all other administrators</button></p>
						<p class="description">Each administrator except you gets a random password nobody knows, their sessions end, their application passwords are revoked, and WordPress emails them the standard reset link. Warn your team first so the email is not mistaken for phishing.</p>
					</td>
				</tr>
				<tr>
					<th scope="row">Log everyone out</th>
					<td>
						<p><button class="button mcss-act" data-action="mcss_logout_all" data-logout="1" data-confirm="End every login session on the site, including yours?">End all sessions</button></p>
						<p class="description">The fallback for hosts where wp-config.php cannot be edited. Same effect on sessions as rotating salts, with no file change.</p>
					</td>
				</tr>
			</tbody></table>
		</div>

		<div class="card">
			<h2>Quarantine</h2>
			<?php if ( empty( $items ) ) : ?>
				<p>Empty. Files you quarantine or repair from the Scan tab are kept here so you can inspect or restore them.</p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr><th>Original location</th><th>Why</th><th>When</th><th>By</th><th style="width:120px"></th></tr></thead>
					<tbody>
					<?php foreach ( $items as $id => $it ) : ?>
						<tr>
							<td><code><?php echo esc_html( $it['orig'] ); ?></code><br><span class="snip"><?php echo $it['kind'] === 'dir' ? 'whole folder, stored as ' . esc_html( $id ) . '.dir' : ( $it['kind'] === 'option' ? 'value kept in this record: ' . esc_html( mb_substr( (string) $it['value'], 0, 160 ) ) : 'md5 ' . esc_html( $it['md5'] ) . ', stored as ' . esc_html( $id ) . '.quarantined' ); ?></span></td>
							<td><?php echo esc_html( $it['title'] ); ?></td>
							<td><?php echo esc_html( wp_date( 'M j, Y H:i', (int) $it['time'] ) ); ?></td>
							<td><?php echo esc_html( $it['user'] ); ?></td>
							<td class="acts">
								<a href="#" class="mcss-act" data-action="mcss_restore" data-id="<?php echo esc_attr( $id ); ?>" data-hide="1" data-confirm="<?php echo $it['kind'] === 'replaced' ? 'Put the MODIFIED copy back over the official file?' : ( $it['kind'] === 'dir' ? 'Move this plugin folder back and reactivate it if it was active?' : ( $it['kind'] === 'option' ? 'Put this option back in the database?' : 'Move this file back to where it was?' ) ); ?>">Restore</a>
								<a href="#" class="mcss-act" data-action="mcss_purge" data-id="<?php echo esc_attr( $id ); ?>" data-hide="1" data-confirm="Delete this quarantined file for good?">Delete for good</a>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<p class="description">Stored in <code>wp-content/mcss-quarantine</code> with a non-executable extension. Keep infected files until the investigation is finished. They are the evidence.</p>
			<?php endif; ?>
		</div>
		<?php
	}

	private static function tab_hardening( $running ) {
		$s      = MCSS_Scanner::settings();
		$notice = get_transient( 'mcss_notice_' . get_current_user_id() );
		delete_transient( 'mcss_notice_' . get_current_user_id() );
		$rows = array(
			'h_file_edit' => array( 'Turn off the theme and plugin file editor', 'An attacker with an admin login uses it to write PHP straight into the site.' . ( defined( 'DISALLOW_FILE_EDIT' ) && empty( $s['h_file_edit'] ) ? ' Already set in wp-config.php on this site.' : '' ) ),
			'h_xmlrpc'    => array( 'Turn off XML-RPC logins and pingbacks', 'Stops password guessing and pingback abuse through xmlrpc.php. Leave off if you use Jetpack or the WordPress mobile app.' ),
			'h_enum'      => array( 'Block username discovery', 'Stops ?author=1 scans, hides the users REST endpoint from visitors who are not logged in, and removes the users sitemap.' ),
			'h_app_pw'    => array( 'Turn off application passwords', 'Removes an API login route that survives password resets. Leave off if you connect tools to this site through the REST API, including AI or MCP connectors.' ),
			'h_version'   => array( 'Hide the WordPress version', 'Removes the generator tag from pages and feeds.' ),
			'h_headers'   => array( 'Send basic security headers', 'X-Content-Type-Options, X-Frame-Options SAMEORIGIN and Referrer-Policy. Leave off if other sites embed this one in an iframe.' ),
			'h_uploads'   => array( 'Block PHP from running in uploads', MCSS_Harden::htaccess_supported() ? 'Adds a rule to wp-content/uploads/.htaccess. It is tested with a probe file and removed again if uploads stop being served.' : 'Not available: this server does not read .htaccess files. Ask the host to block PHP execution in uploads.' ),
		);
		?>
		<div class="card">
			<h2>Hardening</h2>
			<?php if ( defined( 'MCSS_DISABLE_HARDENING' ) && MCSS_DISABLE_HARDENING ) : ?>
				<p><strong>All switches are bypassed because MCSS_DISABLE_HARDENING is set in wp-config.php.</strong></p>
			<?php endif; ?>
			<?php if ( $notice ) : ?><p style="color:#b32d2e"><strong><?php echo esc_html( $notice ); ?></strong></p><?php endif; ?>
			<p class="description">Everything is off until you turn it on. Apart from the uploads rule these are runtime filters, so nothing is written to disk and switching one off undoes it completely. If a switch ever locks you out, add <code>define( 'MCSS_DISABLE_HARDENING', true );</code> to wp-config.php.</p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="mcss_save_hardening">
				<?php wp_nonce_field( 'mcss_save_hardening' ); ?>
				<table class="form-table" role="presentation"><tbody>
				<?php foreach ( $rows as $k => $row ) : ?>
					<tr>
						<th scope="row"><label><input type="checkbox" name="<?php echo esc_attr( $k ); ?>" value="1" <?php checked( $s[ $k ], 1 ); ?> <?php disabled( $k === 'h_uploads' && ! MCSS_Harden::htaccess_supported() && empty( $s[ $k ] ) ); ?>> <?php echo esc_html( $row[0] ); ?></label></th>
						<td><p class="description"><?php echo esc_html( $row[1] ); ?></p></td>
					</tr>
				<?php endforeach; ?>
				</tbody></table>
				<p><button class="button button-primary">Save</button><?php echo isset( $_GET['saved'] ) ? ' Saved.' : ''; // phpcs:ignore ?></p>
			</form>
		</div>
		<?php
	}

	private static function tab_report( $running ) {
		$view = wp_nonce_url( admin_url( 'admin-post.php?action=mcss_client_report' ), 'mcss_client_report' );
		?>
		<div class="card">
			<h2>Client report</h2>
			<p>A one-page status report written for the site owner, not for a developer. It lists every plugin with its update state in plain language, calls out the ones that are not getting updates because a licence is missing or expired, and lists every administrator account with a "keep?" column for the client to fill in.</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( $view ); ?>" target="_blank" rel="noopener">Open report</a>
				<a class="button" href="<?php echo esc_url( $view . '&download=1' ); ?>">Download as HTML</a>
			</p>
			<p class="description">The report opens in a new tab with a print button; "save as PDF" from the print dialog gives you something to email. It checks wordpress.org for each free plugin's latest version and last release date (cached for a day), so the first open can take twenty or thirty seconds on a site with many plugins. Nothing on the site is changed.</p>
			<p class="description">How licence problems are detected: when WordPress knows an update exists but the plugin's update server refuses to supply the download, the plugin is marked "Licence problem". That is the exact symptom of an expired or missing licence. Premium plugins whose updater never checks in are marked "Could not confirm", with a note to check the licence in the plugin's own settings.</p>
		</div>
		<?php
	}

	private static function tab_settings( $running ) {
		$s = MCSS_Scanner::settings();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="mcss_save">
			<?php wp_nonce_field( 'mcss_save' ); ?>
			<div class="card">
				<h2>Alerts</h2>
				<p><label>Send alerts to <input type="email" name="email" class="regular-text" value="<?php echo esc_attr( $s['email'] ); ?>"></label></p>
				<p><label><input type="checkbox" name="alert_admins" value="1" <?php checked( $s['alert_admins'], 1 ); ?>> The moment an administrator is created or promoted, an administrator's email changes, or an administrator gets an application password</label></p>
				<p><label><input type="checkbox" name="alert_plugins" value="1" <?php checked( $s['alert_plugins'], 1 ); ?>> When a plugin or theme is installed, or a plugin is activated or deactivated</label></p>
				<p><label><input type="checkbox" name="alert_files" value="1" <?php checked( $s['alert_files'], 1 ); ?>> Hourly, when a file is added, changed or removed in must-use plugins, drop-ins, the site root or wp-config.php</label></p>
				<p><label><input type="checkbox" name="daily" value="1" <?php checked( $s['daily'], 1 ); ?>> Run a full background scan once a day and email me when a new high severity finding appears</label></p>
				<p class="description">At most 12 alert emails an hour. Everything is in the activity log either way.</p>
			</div>
			<div class="card">
				<h2>Scan options</h2>
				<p><label><input type="checkbox" name="render" value="1" <?php checked( $s['render'], 1 ); ?>> Load live pages as a visitor, as Googlebot and as a visitor arriving from Google, and compare them</label></p>
				<p><label>Extra pages to check, one per line (the home page and a 404 page are always checked)<br><textarea name="render_urls" rows="4" class="large-text code" placeholder="/contact/"><?php echo esc_textarea( $s['render_urls'] ); ?></textarea></label></p>
				<p><label><input type="checkbox" name="vuln" value="1" <?php checked( $s['vuln'], 1 ); ?>> Check installed plugin, theme and core versions against the WPVulnerability database, and flag closed or abandoned plugins</label></p>
				<p class="description">That check sends plugin and theme slugs to wpvulnerability.net and api.wordpress.org. The site address is not sent.</p>
				<p><label>Keep the activity log for <input type="number" name="log_days" min="7" max="730" value="<?php echo (int) $s['log_days']; ?>" style="width:80px"> days</label></p>
			</div>
			<div class="card">
				<h2>Central reporting</h2>
				<p><label>Webhook URL (https)<br><input type="url" name="webhook" class="large-text code" value="<?php echo esc_attr( $s['webhook'] ); ?>" placeholder="https://"></label></p>
				<p><label>Signing secret<br><input type="text" name="secret" class="regular-text code" value="<?php echo esc_attr( $s['secret'] ); ?>" autocomplete="off"></label></p>
				<p class="description">Every finished scan, every alert and a daily heartbeat are posted here as JSON, signed with HMAC SHA-256 in the <code>X-MCSS-Signature</code> header. Slack and Discord webhook URLs are detected and get a readable message instead. Point every client site at one endpoint and a site that goes quiet is a site to look at.</p>
				<p><button class="button mcss-act" data-action="mcss_test_webhook" data-confirm="Send a test message to the saved webhook URL?">Send test</button></p>
			</div>
			<?php $u = MCSS_Update::status(); ?>
			<div class="card">
				<h2>Updates</h2>
				<p>Installed <?php echo esc_html( MCSS_Scanner::VERSION ); ?><?php echo $u['latest'] !== '' ? ', latest release ' . esc_html( $u['latest'] ) : ''; ?>. Detection rules <?php echo esc_html( $u['rules_sha'] ); ?><?php echo $u['rules_updated'] ? ', last changed ' . esc_html( wp_date( 'M j, Y', $u['rules_updated'] ) ) : ''; ?>, last checked <?php echo $u['rules_checked'] ? esc_html( wp_date( 'M j, Y H:i', $u['rules_checked'] ) ) : 'never'; ?>.</p>
				<p><label><input type="checkbox" name="auto_update" value="1" <?php checked( $s['auto_update'], 1 ); ?>> Install new releases of this plugin automatically</label></p>
				<p class="description">Releases come from GitHub and are only installed when their signature verifies against the key built into this plugin. Detection rules update the same way once a day, with no plugin release needed. <?php echo $u['signing'] ? 'Signature checking is working on this host.' : '<strong style="color:#b32d2e">This host cannot verify signatures, so network updates are refused. Update by uploading the zip.</strong>'; ?></p>
				<p><button class="button mcss-act" data-action="mcss_check_updates" data-confirm="Check GitHub for a new release and new rules now?">Check now</button></p>
			</div>
			<p><button class="button button-primary">Save settings</button><?php echo isset( $_GET['saved'] ) ? ' Saved.' : ''; // phpcs:ignore ?></p>
		</form>
		<?php
	}

	private static function script( $running ) {
		?>
		<script>
		(function(){
			var ajax = <?php echo wp_json_encode( admin_url( 'admin-ajax.php' ) ); ?>, nonce = <?php echo wp_json_encode( wp_create_nonce( 'mcss' ) ); ?>;
			var loginUrl = <?php echo wp_json_encode( wp_login_url( admin_url( 'tools.php?page=mcss' ) ) ); ?>;
			var resume = <?php echo $running ? 'true' : 'false'; ?>;
			function post(action, extra){
				var body = new URLSearchParams(Object.assign({action: action, nonce: nonce}, extra || {}));
				return fetch(ajax, {method: 'POST', credentials: 'same-origin', body: body}).then(function(r){ return r.json(); });
			}
			var btn = document.getElementById('mcss-run');
			if (btn) {
				var box = document.getElementById('mcss-progress'), bar = box.querySelector('i'), label = document.getElementById('mcss-label'), fails = 0;
				var show = function(p){ bar.style.width = (p.pct || 0) + '%'; label.textContent = p.label || ''; };
				var loop = function(){
					post('mcss_step').then(function(res){
						if (!res || !res.success) { throw new Error('bad response'); }
						fails = 0; show(res.data);
						if (res.data.done) { label.textContent = 'Finished. Loading results.'; window.location.reload(); return; }
						setTimeout(loop, res.data.busy ? 3000 : 250);
					}).catch(function(){
						fails++;
						if (fails > 5) { label.textContent = 'The server stopped responding. Nothing was changed. Reload this page and press Resume scan.'; btn.disabled = false; return; }
						setTimeout(loop, 4000);
					});
				};
				btn.addEventListener('click', function(e){
					e.preventDefault(); btn.disabled = true; box.style.display = 'block';
					if (resume) { label.textContent = 'Resuming'; loop(); return; }
					label.textContent = 'Starting';
					post('mcss_start').then(function(res){ if (res && res.success) { show(res.data); loop(); } else { label.textContent = 'Could not start the scan.'; btn.disabled = false; } })
						.catch(function(){ label.textContent = 'Could not start the scan.'; btn.disabled = false; });
				});
			}
			var actMsg = document.getElementById('mcss-act-msg');
			document.querySelectorAll('.mcss-act').forEach(function(b){
				b.addEventListener('click', function(e){
					e.preventDefault();
					if (b.getAttribute('data-busy')) { return; }
					if (!window.confirm(b.getAttribute('data-confirm'))) { return; }
					b.setAttribute('data-busy', '1'); actMsg.style.color = ''; actMsg.textContent = 'Working. This can take up to half a minute while the site is checked.';
					var extra = {};
					if (b.getAttribute('data-k')) { extra.k = b.getAttribute('data-k'); }
					if (b.getAttribute('data-id')) { extra.id = b.getAttribute('data-id'); }
					if (b.getAttribute('data-kind')) { extra.kind = b.getAttribute('data-kind'); }
					post(b.getAttribute('data-action'), extra).then(function(res){
						var msg = res && res.data && res.data.message ? res.data.message : 'No response.';
						actMsg.style.color = res && res.success ? '#007017' : '#b32d2e';
						actMsg.textContent = msg;
						b.removeAttribute('data-busy');
						if (res && res.success && b.getAttribute('data-logout')) {
							actMsg.textContent = msg + ' Sending you to the login screen.';
							setTimeout(function(){ window.location.href = loginUrl; }, 6000);
						} else if (res && res.success && b.getAttribute('data-hide')) {
							var tr = b.closest('tr'); if (tr) { tr.style.display = 'none'; }
						}
					}).catch(function(){ actMsg.style.color = '#b32d2e'; actMsg.textContent = 'The request failed. Reload the page to see whether it went through.'; b.removeAttribute('data-busy'); });
				});
			});
			document.querySelectorAll('.mcss-ignore').forEach(function(a){
				a.addEventListener('click', function(e){
					e.preventDefault();
					post('mcss_ignore', {k: a.getAttribute('data-k')}).then(function(res){ if (res && res.success) { a.closest('tr').style.display = 'none'; } });
				});
			});
		})();
		</script>
		<?php
	}
}


MCSS_Scanner::init();
MCSS_Log::hooks();
MCSS_Alerts::hooks();
MCSS_Admin::hooks();
MCSS_Harden::boot();
MCSS_Update::hooks();
register_activation_hook( __FILE__, array( 'MCSS_Admin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'MCSS_Scanner', 'deactivate' ) );

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	/**
	 * wp mcss scan [--format=text|json]
	 */
	WP_CLI::add_command(
		'mcss scan',
		function ( $args, $assoc ) {
			if ( ! MCSS_Scanner::lock() ) {
				WP_CLI::error( 'Another scan step is running. Try again in a minute.' );
			}
			MCSS_Scanner::start( 'cli' );
			$lastlabel = '';
			$loops     = 0;
			do {
				$state = MCSS_Scanner::step( 20 );
				if ( empty( $state ) || ++$loops > 5000 ) {
					MCSS_Scanner::unlock();
					WP_CLI::error( 'The scan state was lost or the scan is not making progress.' );
				}
				$p     = MCSS_Scanner::progress( $state );
				$phase = isset( $state['phase'] ) ? $state['phase'] : '';
				if ( $phase !== $lastlabel ) {
					WP_CLI::log( $p['label'] );
					$lastlabel = $phase;
				}
			} while ( empty( $state['done'] ) );
			MCSS_Scanner::unlock();
			if ( isset( $assoc['format'] ) && $assoc['format'] === 'json' ) {
				WP_CLI::line( wp_json_encode( array_values( MCSS_Scanner::visible_findings() ) ) );
			} else {
				WP_CLI::line( MCSS_Scanner::text_report() );
			}
		}
	);
}

	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		/** wp mcss rotate-salts */
		WP_CLI::add_command(
			'mcss rotate-salts',
			function () {
				$r = MCSS_Scanner::rotate_salts();
				$r['ok'] ? WP_CLI::success( $r['message'] ) : WP_CLI::error( $r['message'] );
			}
		);
		/** wp mcss reset-admins [--keep=<user_id>] */
		WP_CLI::add_command(
			'mcss reset-admins',
			function ( $args, $assoc ) {
				$r = MCSS_Scanner::reset_admin_passwords( isset( $assoc['keep'] ) ? (int) $assoc['keep'] : 0 );
				WP_CLI::success( $r['message'] );
			}
		);
	}

endif;
