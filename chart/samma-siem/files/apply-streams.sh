#!/bin/sh
# Creates or edits every stream and consumer in /config (the ConfigMap
# <release>-streams). Idempotent: what is missing is added, what exists is
# edited to match its config. Streams first, so a consumer's stream exists.
set -eu
dir=${CONFIG_DIR:-/config}

# NATS may still be starting on a fresh install.
i=0
until nats account info >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    echo "JetStream at $NATS_URL not reachable after 5 minutes" >&2
    nats account info >&2 || true
    exit 1
  fi
  sleep 5
done

for f in "$dir"/stream.*.json; do
  [ -e "$f" ] || continue
  name=${f##*/stream.}
  name=${name%.json}
  if nats stream info "$name" >/dev/null 2>&1; then
    echo "stream $name: edit"
    nats stream edit "$name" --config "$f" -f >/dev/null
  else
    echo "stream $name: add"
    nats stream add "$name" --config "$f" >/dev/null
  fi
done

for f in "$dir"/consumer.*.json; do
  [ -e "$f" ] || continue
  rest=${f##*/consumer.}
  rest=${rest%.json}
  stream=${rest%%.*}
  name=${rest#*.}
  if nats consumer info "$stream" "$name" >/dev/null 2>&1; then
    echo "consumer $stream $name: edit"
    nats consumer edit "$stream" "$name" --config "$f" -f >/dev/null
  else
    echo "consumer $stream $name: add"
    nats consumer add "$stream" "$name" --config "$f" >/dev/null
  fi
done

nats stream ls
for f in "$dir"/stream.*.json; do
  [ -e "$f" ] || continue
  name=${f##*/stream.}
  nats consumer ls "${name%.json}"
done
