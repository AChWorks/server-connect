#!/bin/sh
# Called only from product_tun_trial in the disconnected Debian13 guest.
# The Python driver shares that fixture's peer and native baseline, while
# retaining separate operation-bound confirmation and supervision evidence.
supervised_product_tun_trial() {
  set -- --profile "$profile" --upstream-pid "$server_pid"
  if [ "$ipv6_trial" = yes ]; then set -- "$@" --ipv6; fi
  /usr/bin/python3 -I -B -u /root/qa-supervised-product-tun.py "$@"
  require_finalized
}
