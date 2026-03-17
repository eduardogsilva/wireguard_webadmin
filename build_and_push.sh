#!/bin/bash

# Format: "service|image|manual"
# Entries with "manual" as third field are excluded from "All" and must be selected individually.
SERVICES=(
  "wireguard-webadmin|eduardosilva/wireguard_webadmin|"
  "wireguard-webadmin-cron|eduardosilva/wireguard_webadmin_cron|"
  "wireguard-webadmin-dns|eduardosilva/wireguard_webadmin_dns|"
  "wireguard-webadmin-nginx|eduardosilva/wireguard_webadmin_nginx|"
  "wireguard-webadmin-rrdtool|eduardosilva/wireguard_webadmin_rrdtool|"
  "wireguard-webadmin-caddy|eduardosilva/wireguard_webadmin_caddy|"
  "wireguard-webadmin-auth-gateway|eduardosilva/wireguard_webadmin_auth_gateway|"
  "wireguard-webadmin-cluster-node|eduardosilva/wireguard-webadmin-cluster-node|manual"
)

SEP="=================================================================="

# ── Tag selection ──
echo ""
echo "$SEP"
echo "  Tag:"
echo "  1) latest  (default)"
echo "  2) testing"
echo "$SEP"
printf "Choice [1]: "
read tag_choice

case "$tag_choice" in
  2) TAG="testing" ;;
  *) TAG="latest" ;;
esac

# ── Image selection ──
echo ""
echo "$SEP"
echo "  Image to build and push:"
echo "  0) All images  (default, excludes manual-only)"
i=1
for entry in "${SERVICES[@]}"; do
  IFS="|" read -r SVC IMG FLAG <<< "$entry"
  if [ "$FLAG" = "manual" ]; then
    printf "  %d) %s  [manual only]\n" "$i" "$SVC"
  else
    printf "  %d) %s\n" "$i" "$SVC"
  fi
  i=$((i + 1))
done
echo "$SEP"
printf "Choice [0]: "
read img_choice

if [ -z "$img_choice" ] || [ "$img_choice" = "0" ]; then
  SELECTED=()
  for entry in "${SERVICES[@]}"; do
    IFS="|" read -r SVC IMG FLAG <<< "$entry"
    [ "$FLAG" != "manual" ] && SELECTED+=("$entry")
  done
  BUILD_SVC=""
else
  if ! echo "$img_choice" | grep -qE '^[0-9]+$'; then
    echo "Invalid choice." && exit 1
  fi
  idx=$((img_choice - 1))
  if [ "$idx" -lt 0 ] || [ "$idx" -ge "${#SERVICES[@]}" ]; then
    echo "Invalid choice." && exit 1
  fi
  SELECTED=("${SERVICES[$idx]}")
  BUILD_SVC="${SERVICES[$idx]%%|*}"
fi

# ── Confirm ──
echo ""
echo "$SEP"
echo "  Tag  : $TAG"
echo "  Images:"
for entry in "${SELECTED[@]}"; do
  IFS="|" read -r SVC IMG FLAG <<< "$entry"
  printf "    - %s:%s\n" "$IMG" "$TAG"
done
echo "$SEP"
printf "Confirm? [y/N]: "
read confirm
case "$confirm" in
  [yY]*) ;;
  *) echo "Aborted." && exit 0 ;;
esac

# ── Prune ──
echo ""
echo "$SEP"
echo "Pruning Docker system..."
docker system prune -a

# ── Build ──
echo ""
echo "$SEP"
echo "Building..."
cat .gitignore > .dockerignore
TAG=$TAG docker compose -f docker-compose-build.yml build $BUILD_SVC
if [ $? -ne 0 ]; then
  echo "Build failed." && exit 1
fi

# ── Push ──
echo ""
echo "$SEP"
echo "Pushing..."
for entry in "${SELECTED[@]}"; do
  IFS="|" read -r SVC IMAGE FLAG <<< "$entry"
  IMAGE="$IMAGE:$TAG"
  echo ""
  echo "--- Pushing $IMAGE..."
  docker push "$IMAGE"
  if [ $? -ne 0 ]; then
    echo "ERROR pushing $IMAGE" && exit 1
  fi
  echo "--- $IMAGE pushed successfully."
done

echo ""
echo "$SEP"
echo "Done. Tag: $TAG"
