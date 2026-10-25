#!/bin/sh
# Installed Server Connect + genuine WordPress/PHP-FPM over isolated VLESS.
# CI-only disposable Debian 13 systemd guest with Docker --network none.
# All WP_PROXY_* configuration belongs ONLY to this disposable QA fixture.
set -eu
umask 077

site=/var/lib/sc-qa-wp/site
fpm_unit=sc-qa-wp-fpm.service
origin_unit=sc-qa-wp-origin.service
socket=/run/sc-qa-wp-fpm.sock
manager=/usr/local/bin/server-connect
origin=http://127.0.0.2:19185/nonce
stage=init
# A failed 'test' under set -e is otherwise silent in privileged CI logs.
# Stage is a fixed non-secret label; no WordPress credentials or URLs logged.
report_failure() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "INSTALLED_WORDPRESS_FPM_FAILURE(stage=$stage,exit=$status)" >&2
  fi
}
trap report_failure EXIT

require_guest() {
  stage=guest-root
  test "$(id -u)" -eq 0
  stage=guest-systemd
  test "$(ps -p 1 -o comm=)" = systemd
  stage=guest-script
  test -f /root/qa-wp-fpm.sh
  stage=installed-manager
  test -x "$manager"
  # Require the Docker --network none guest's loopback-only interface set.
  # Exact route text is not a stable guard after a systemd/VLESS lifecycle;
  # the parent harness independently hashes the complete guest route/rule/link
  # inventory against its pre-product baseline before and after this fixture.
  stage=guest-netns-isolation
  test "$(ls -1 /sys/class/net)" = lo
  stage=guest-ipv6-default
  test -z "$(ip -6 route show default)"
}

direct_nonce() {
  nonce=$1
  body=$(curl -q --noproxy '*' --fail --silent --show-error \
    --max-time 3 "$origin?value=$nonce") || return 1
  test "$body" = "SC_QA_WP_NONCE:$nonce"
}

assert_fpm_selected() {
  expectation=$1
  phase=$2
  stage="selected-$phase:service-active"
  systemctl is-active --quiet "$fpm_unit"
  systemctl is-active --quiet "$origin_unit"
  nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
  test "$(printf %s "$nonce" | wc -c)" -eq 16
  stage="selected-$phase:direct-origin"
  direct_nonce "$nonce"
  # Fail closed on a missing FastCGI executable, nonzero return or missing JSON.
  stage="selected-$phase:fastcgi"
  result=$(timeout --kill-after=2s 12s /usr/bin/env -i \
    REQUEST_METHOD=GET SCRIPT_FILENAME="$site/qa-http.php" \
    SCRIPT_NAME=/qa-http.php QUERY_STRING="nonce=$nonce" \
    SERVER_NAME=localhost SERVER_PORT=80 SERVER_PROTOCOL=HTTP/1.1 \
    DOCUMENT_ROOT="$site" CONTENT_LENGTH=0 \
    /usr/bin/cgi-fcgi -bind -connect "$socket") || {
      echo "WORDPRESS_FPM($phase)=FAIL (FastCGI invocation)" >&2
      return 1
    }
  printf '%s\n' "$result" | python3 /root/qa-wp-fcgi-check.py "$expectation" "$phase"
}

setup() {
  require_guest
  stage=wordpress-fixture
  test -d /opt/sc-qa-wordpress-core
  stage=php-native-binaries
  test -x /usr/sbin/php-fpm8.4
  test -x /usr/bin/cgi-fcgi
  test -x /usr/bin/php
  stage=fixture-collisions
  test ! -e /var/lib/sc-qa-wp
  test ! -e "$socket"
  stage=fixture-copy
  mkdir -m 0755 /var/lib/sc-qa-wp
  cp -a /opt/sc-qa-wordpress-core "$site"
  # Only the disposable SQLite database directory is writable by the worker.
  install -d -m 0700 -o www-data -g www-data "$site/wp-content/database"
  cat > "$site/wp-config.php" <<'PHP'
<?php
// Disposable QA-only WordPress installation; not a customer configuration.
define('DB_NAME', 'sc_qa');
define('DB_USER', 'sc_qa');
define('DB_PASSWORD', 'not-a-real-credential');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('AUTH_KEY', 'scqa-unit-only-auth');
define('SECURE_AUTH_KEY', 'scqa-unit-only-secure-auth');
define('LOGGED_IN_KEY', 'scqa-unit-only-logged-in');
define('NONCE_KEY', 'scqa-unit-only-nonce');
define('AUTH_SALT', 'scqa-unit-only-auth-salt');
define('SECURE_AUTH_SALT', 'scqa-unit-only-secure-salt');
define('LOGGED_IN_SALT', 'scqa-unit-only-logged-in-salt');
define('NONCE_SALT', 'scqa-unit-only-nonce-salt');
define('WP_HOME', 'http://localhost');
define('WP_SITEURL', 'http://localhost');
define('DISABLE_WP_CRON', true);
define('WP_AUTO_UPDATE_CORE', false);
define('DISALLOW_FILE_MODS', true);
$table_prefix = 'wp_';
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
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
    wp_install('Isolated QA', 'qaadmin', 'qa@example.invalid', false, '', 'local-only-password');
}
if (!is_blog_installed()) {
    exit(1);
}
echo "WORDPRESS_SQLITE_INSTALLED=PASS\n";
PHP
  chmod 0644 "$site/qa-init.php"
  # Real WordPress install, not a mocked API or a hand-written HTTP client.
  stage=wordpress-db-install
  /usr/sbin/runuser -u www-data -- /usr/bin/php "$site/qa-init.php"
  rm -f "$site/qa-init.php"

  cat > /var/lib/sc-qa-wp/proxy-prepend.php <<'PHP'
<?php
// QA-only, FPM-pool-local settings. The product does NOT edit WordPress.
define('WP_PROXY_HOST', '127.0.0.1');
define('WP_PROXY_PORT', 20807);
define('WP_PROXY_BYPASS_HOSTS', 'localhost');
PHP
  chown root:www-data /var/lib/sc-qa-wp/proxy-prepend.php
  chmod 0640 /var/lib/sc-qa-wp/proxy-prepend.php

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
$target = 'http://127.0.0.2:19185/nonce?value=' . $nonce;
$proxy = new WP_HTTP_Proxy();
$result = wp_remote_get($target, ['timeout' => 4, 'redirection' => 0, 'headers' => ['Cache-Control' => 'no-cache']]);
$code = is_wp_error($result) ? 502 : (int) wp_remote_retrieve_response_code($result);
$body = is_wp_error($result) ? '' : wp_remote_retrieve_body($result);
$matches = ($code === 200 && $body === 'SC_QA_WP_NONCE:' . $nonce);
http_response_code($code === 200 && $matches ? 200 : 502);
echo wp_json_encode([
    'php_sapi' => PHP_SAPI,
    'wp_installed' => is_blog_installed(),
    'proxy_enabled' => $proxy->is_enabled(),
    'proxy_selected' => $proxy->send_through_proxy($target),
    'localhost_exempt' => !$proxy->send_through_proxy('http://localhost:19185/'),
    'status' => $code,
    'nonce_match' => $matches,
]);
PHP
  chmod 0644 "$site/qa-http.php"

  cat > /root/qa-wp-fpm.conf <<'CONF'
[global]
pid = /run/sc-qa-wp-fpm.pid
error_log = /dev/stderr
daemonize = no
[scqa]
user = www-data
group = www-data
listen = /run/sc-qa-wp-fpm.sock
listen.owner = root
listen.group = root
listen.mode = 0600
pm = static
pm.max_children = 2
clear_env = yes
chdir = /var/lib/sc-qa-wp/site
security.limit_extensions = .php
php_admin_value[auto_prepend_file] = /var/lib/sc-qa-wp/proxy-prepend.php
CONF
  chmod 0600 /root/qa-wp-fpm.conf
  stage=fpm-config-validation
  /usr/sbin/php-fpm8.4 --test --fpm-config /root/qa-wp-fpm.conf

  cat > /run/systemd/system/sc-qa-wp-origin.service <<'UNIT'
[Unit]
Description=Disposable QA WordPress nonce origin
[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /root/qa-wp-nonce-origin.py
Restart=no
UNIT
  cat > /run/systemd/system/sc-qa-wp-fpm.service <<'UNIT'
[Unit]
Description=Disposable QA WordPress PHP-FPM pool
[Service]
Type=simple
ExecStart=/usr/sbin/php-fpm8.4 --nodaemonize --fpm-config /root/qa-wp-fpm.conf
Restart=no
UNIT
  chmod 0644 /run/systemd/system/sc-qa-wp-*.service
  stage=fpm-origin-unit-start
  systemctl daemon-reload
  systemctl start "$origin_unit" "$fpm_unit"
  ready=no
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if systemctl is-active --quiet "$origin_unit" &&
       systemctl is-active --quiet "$fpm_unit" &&
       test -S "$socket" &&
       direct_nonce 0000000000000000; then
      ready=yes
      break
    fi
    sleep 1
  done
  test "$ready" = yes || { echo 'Isolated WordPress FPM/origin startup failed' >&2; exit 1; }
  stage=first-fpm-request
  assert_fpm_selected positive initial
}

upstream_failure() {
  phase=$1
  assert_fpm_selected positive "$phase-before-stop"
  systemctl stop sc-qa-vless.service
  if systemctl is-active --quiet sc-qa-vless.service; then return 1; fi
  # FPM and independent Direct origin stay UP while only the selected VLESS dies.
  assert_fpm_selected negative "$phase-upstream-stopped"
  systemctl start sc-qa-vless.service
  assert_fpm_selected positive "$phase-recovered"
}

core_failure() {
  assert_fpm_selected positive before-core-stop
  systemctl stop server-connect.service
  if systemctl is-active --quiet server-connect.service; then return 1; fi
  assert_fpm_selected negative core-stopped
  systemctl start server-connect.service
  assert_fpm_selected positive core-recovered
}

cleanup() {
  # All resources below carry fixed QA-only identities inside the private guest.
  systemctl stop "$fpm_unit" "$origin_unit"
  test ! -S "$socket"
  rm -f /run/systemd/system/sc-qa-wp-fpm.service /run/systemd/system/sc-qa-wp-origin.service
  systemctl daemon-reload
  test -f "$site/wp-config.php"
  rm -rf -- /var/lib/sc-qa-wp
  test ! -e /var/lib/sc-qa-wp
  echo 'ISOLATED_WORDPRESS_FPM_FIXTURE_CLEANUP=PASS'
}

require_guest
case "$1" in
  setup) test "$#" -eq 1; setup ;;
  positive) test "$#" -eq 2; assert_fpm_selected positive "$2" ;;
  upstream-failure) test "$#" -eq 2; upstream_failure "$2" ;;
  core-failure) test "$#" -eq 1; core_failure ;;
  negative-disconnected) test "$#" -eq 1; assert_fpm_selected negative disconnected ;;
  cleanup) test "$#" -eq 1; cleanup ;;
  *) echo 'Usage: host-wordpress-fpm.sh setup|positive PHASE|upstream-failure PHASE|core-failure|negative-disconnected|cleanup' >&2; exit 2 ;;
esac
