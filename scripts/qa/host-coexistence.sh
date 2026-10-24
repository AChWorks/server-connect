#!/bin/sh
# Disposable Debian 13 CI fixture only. The caller must first create an
# isolated Docker --network none container and enable its private loopback.
# Neither service binds an external or host-accessible interface.
set -eu
umask 077

case "${1:-}" in
  start)
    test "$#" -eq 1
    test "$(ps -p 1 -o comm=)" = systemd
    test -z "$(ip -4 route show default)"
    test -z "$(ip -6 route show default)"
    ip -4 address show dev lo | grep -F '127.0.0.1/8' >/dev/null
    mkdir -m 0700 /root/qa-ssh /root/qa-web
    mkdir -p /run/sshd
    chmod 0755 /run/sshd
    printf '%s\n' SC_QA_WEB_OK > /root/qa-web/index.html
    ssh-keygen -q -t ed25519 -N '' -f /root/qa-ssh/hostkey
    ssh-keygen -q -t ed25519 -N '' -f /root/qa-ssh/clientkey
    mkdir -m 0700 /home/scqa/.ssh
    cp /root/qa-ssh/clientkey.pub /home/scqa/.ssh/authorized_keys
    chown -R scqa:scqa /home/scqa/.ssh
    chmod 0600 /home/scqa/.ssh/authorized_keys
    printf '[127.0.0.1]:19222 %s\n' "$(cat /root/qa-ssh/hostkey.pub)" > /root/qa-ssh/known_hosts
    cat > /root/qa-ssh/sshd_config <<'CONF'
ListenAddress 127.0.0.1
Port 19222
HostKey /root/qa-ssh/hostkey
PidFile /run/sc-qa-sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
AllowUsers scqa
PrintMotd no
LogLevel ERROR
CONF
    chmod 0600 /root/qa-ssh/known_hosts /root/qa-ssh/sshd_config
    /usr/sbin/sshd -t -f /root/qa-ssh/sshd_config
    # Native transient systemd units persist across installer's daemon-reload.
    # These are separate, non-product-owned listeners in the disposable guest.
    systemd-run --quiet --unit=sc-qa-ssh --property=Restart=no \
      /usr/sbin/sshd -D -e -f /root/qa-ssh/sshd_config
    systemd-run --quiet --unit=sc-qa-web --property=Restart=no \
      /usr/bin/python3 -m http.server 19180 --bind 127.0.0.1 \
        --directory /root/qa-web
    ;;
  probe)
    test "$#" -eq 1
    systemctl is-active --quiet sc-qa-ssh.service
    systemctl is-active --quiet sc-qa-web.service
    # A matching stdout marker is insufficient if curl later fails. Keep the
    # command status separate from the response-body assertion.
    http_response=$(curl -q --fail --silent --show-error --max-time 3 \
      --noproxy '*' http://127.0.0.1:19180/index.html) || exit 1
    test "$http_response" = SC_QA_WEB_OK || exit 1
    # This is a NEW authenticated SSH connection at every lifecycle phase.
    # Known-host verification is pinned to the locally generated host key.
    ssh_response=$(timeout 8 ssh -F /dev/null -i /root/qa-ssh/clientkey \
      -p 19222 -o BatchMode=yes -o IdentitiesOnly=yes \
      -o ConnectTimeout=3 -o ConnectionAttempts=1 \
      -o PasswordAuthentication=no -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile=/root/qa-ssh/known_hosts \
      -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR \
      scqa@127.0.0.1 'printf SC_QA_SSH_OK') || exit 1
    test "$ssh_response" = SC_QA_SSH_OK || exit 1
    ;;
  *)
    echo 'Usage: host-coexistence.sh start|probe (isolated CI guest only)' >&2
    exit 2
    ;;
esac
