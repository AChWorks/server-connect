#!/bin/sh
# Genuine WordPress HTTP API in a standalone PHP-FPM pool. Disposable,
# disconnected Debian 13 TUN guest only; no application proxy configuration.
set -eu
umask 077

root=/run/sc-qa-tun-wp
site=$root/site
socket=$root/fpm.sock

setup() {
  test "$(id -u)" -eq 0
  test -f /.dockerenv
  test -d "$root" && test ! -L "$root"
  test ! -e "$site" && test ! -L "$site"
  test -f /opt/sc-qa-wordpress-core/wp-load.php
  test -f /opt/sc-qa-wordpress-core/wp-content/db.php
  test -x /usr/sbin/php-fpm8.4 && test -x /usr/bin/php && test -x /usr/bin/cgi-fcgi
  cp -a /opt/sc-qa-wordpress-core "$site"
  chmod 0755 "$root"
  install -d -m 0700 -o www-data -g www-data "$site/wp-content/database"
  cat > "$site/wp-config.php" <<'PHP'
<?php
// All data and credentials are synthetic; never run against a customer site.
define('DB_NAME', 'sc_qa');
define('DB_USER', 'sc_qa');
define('DB_PASSWORD', 'qa-only');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('AUTH_KEY', 'scqa-only-auth');
define('SECURE_AUTH_KEY', 'scqa-only-secure-auth');
define('LOGGED_IN_KEY', 'scqa-only-login');
define('NONCE_KEY', 'scqa-only-nonce');
define('AUTH_SALT', 'scqa-only-auth-salt');
define('SECURE_AUTH_SALT', 'scqa-only-secure-salt');
define('LOGGED_IN_SALT', 'scqa-only-login-salt');
define('NONCE_SALT', 'scqa-only-nonce-salt');
define('WP_HOME', 'http://localhost');
define('WP_SITEURL', 'http://localhost');
define('DISABLE_WP_CRON', true);
define('WP_AUTO_UPDATE_CORE', false);
define('DISALLOW_FILE_MODS', true);
$table_prefix = 'wp_';
if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }
require_once ABSPATH . 'wp-settings.php';
PHP
  chown root:www-data "$site/wp-config.php"
  chmod 0640 "$site/wp-config.php"
  cat > "$site/qa-init.php" <<'PHP'
<?php
define('WP_INSTALLING', true);
require_once __DIR__ . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
if (!is_blog_installed()) {
    wp_install('Disconnected TUN QA', 'qaadmin', 'qa@example.invalid', false, '', 'local-only-password');
}
if (!is_blog_installed()) { exit(1); }
echo "REAL_TUN_WORDPRESS_INSTALLED=PASS\n";
PHP
  chmod 0644 "$site/qa-init.php"
  /usr/sbin/runuser -u www-data -- /usr/bin/php "$site/qa-init.php"
  rm -- "$site/qa-init.php"
  cat > "$site/qa-http.php" <<'PHP'
<?php
define('WP_USE_THEMES', false);
require_once __DIR__ . '/wp-load.php';
header('Content-Type: application/json');
header('Cache-Control: no-store');
$nonce = $_GET['nonce'] ?? '';
if (!is_string($nonce) || !preg_match('/^[0-9a-f]{16}$/', $nonce)) {
    http_response_code(400);
    exit('{"error":"invalid nonce"}');
}
$target = 'http://8.8.8.8:19187/wp/nonce?value=' . $nonce;
$proxy = new WP_HTTP_Proxy();
// send_through_proxy() is only URL eligibility; WordPress uses an actual
// proxy if is_enabled() is true as well. A foreign URL alone can return true
// here even with no proxy configured. Prove the true enablement state.
$proxyConfigAbsent = !defined('WP_PROXY_HOST') && !defined('WP_PROXY_PORT') &&
    !defined('WP_PROXY_USERNAME') && !defined('WP_PROXY_PASSWORD') &&
    !defined('WP_PROXY_BYPASS_HOSTS');
$proxyEnvAbsent = true;
foreach (['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY',
          'HTTPS_PROXY', 'ALL_PROXY'] as $proxyVar) {
    if (getenv($proxyVar) !== false) { $proxyEnvAbsent = false; }
}
$result = wp_remote_get($target, ['timeout' => 4, 'redirection' => 0,
                                   'headers' => ['Cache-Control' => 'no-cache']]);
$failed = is_wp_error($result);
$code = $failed ? 0 : (int) wp_remote_retrieve_response_code($result);
$body = $failed ? '' : wp_remote_retrieve_body($result);
$source = '';
if (preg_match('/^SC_QA_WP_NONCE:' . $nonce . ';SOURCE=(10\\.254\\.72\\.1|8\\.8\\.8\\.8)$/', $body, $match)) {
    $source = $match[1];
}
$matched = ($code === 200 && $source !== '');
http_response_code($matched ? 200 : 502);
echo wp_json_encode([
    'php_sapi' => PHP_SAPI,
    'wp_installed' => is_blog_installed(),
    'proxy_enabled' => $proxy->is_enabled(),
    'proxy_config_absent' => $proxyConfigAbsent,
    'proxy_environment_absent' => $proxyEnvAbsent,
    'wp_error_code' => $failed ? $result->get_error_code() : '',
    'origin_http_code' => $code,
    'origin_source' => $source,
    'nonce_match' => $matched,
]);
PHP
  chmod 0644 "$site/qa-http.php"
  cat > "$root/fpm.conf" <<'CONF'
[global]
pid = /run/sc-qa-tun-wp/fpm.pid
error_log = /run/sc-qa-tun-wp/fpm-error.log
daemonize = no
[scqa]
user = www-data
group = www-data
listen = /run/sc-qa-tun-wp/fpm.sock
listen.owner = root
listen.group = root
listen.mode = 0600
pm = static
pm.max_children = 2
clear_env = yes
chdir = /run/sc-qa-tun-wp/site
security.limit_extensions = .php
CONF
  /usr/sbin/php-fpm8.4 --test --fpm-config "$root/fpm.conf"
  echo 'REAL_TUN_WORDPRESS_FIXTURE=PASS (installed WordPress, no WP_PROXY settings)'
}

probe() {
  mode=$1 expected=$2
  case "$mode:$expected" in
    positive:10.254.72.1|positive:8.8.8.8|negative:none) ;;
    *) echo 'Invalid WordPress QA expectation' >&2; exit 2 ;;
  esac
  test -S "$socket"
  nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
  test "${#nonce}" -eq 16
  # Per-phase independent origin evidence cannot be carried from the earlier
  # native APT/Git paths or the preceding successful WordPress call.
  /usr/bin/python3 -I -B /root/qa-tun-native-apps.py wp-reset
  result=$(timeout --kill-after=2s 12s env -i \
    REQUEST_METHOD=GET SCRIPT_FILENAME="$site/qa-http.php" \
    SCRIPT_NAME=/qa-http.php QUERY_STRING="nonce=$nonce" \
    SERVER_NAME=localhost SERVER_PORT=80 SERVER_PROTOCOL=HTTP/1.1 \
    DOCUMENT_ROOT="$site" CONTENT_LENGTH=0 \
    /usr/bin/cgi-fcgi -bind -connect "$socket")
  printf '%s\n' "$result" | /usr/bin/python3 -I -B /root/qa-tun-wp-check.py "$mode" "$expected"
  /usr/bin/python3 -I -B /root/qa-tun-native-apps.py wp-check "$expected" "$nonce"
  echo "REAL_TUN_WORDPRESS_${mode}_WITNESS=PASS (WordPress FPM, independently observed path)"
}

case "${1-}" in
  setup) test "$#" -eq 1; setup ;;
  probe) test "$#" -eq 3; probe "$2" "$3" ;;
  *) echo 'Usage: tun-wordpress-fpm.sh setup|probe positive|negative SOURCE' >&2; exit 2 ;;
esac
