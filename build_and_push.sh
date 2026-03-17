#!/bin/bash

# Format: "service|image|flag|context|dockerfile|platforms"
# Leave dockerfile empty if using the default Dockerfile in the context directory.
# Leave platforms empty to use the default (linux/amd64,linux/arm/v7,linux/arm64).
# Entries with "manual" as third field are excluded from "All" and must be selected individually.
SERVICES=(
  "wireguard-webadmin|eduardosilva/wireguard_webadmin||.|"
  "wireguard-webadmin-cron|eduardosilva/wireguard_webadmin_cron||./containers/cron|Dockerfile-cron"
  "wireguard-webadmin-dns|eduardosilva/wireguard_webadmin_dns||./containers/dnsmasq|Dockerfile-dnsmasq"
  "wireguard-webadmin-nginx|eduardosilva/wireguard_webadmin_nginx||.|Dockerfile_nginx"
  "wireguard-webadmin-rrdtool|eduardosilva/wireguard_webadmin_rrdtool||./containers/rrdtool|Dockerfile-rrdtool"
  "wireguard-webadmin-caddy|eduardosilva/wireguard_webadmin_caddy||./containers/caddy|Dockerfile-caddy"
  "wireguard-webadmin-auth-gateway|eduardosilva/wireguard_webadmin_auth_gateway||./containers/auth-gateway|Dockerfile-auth-gateway|"
  "wireguard-webadmin-cluster-node|eduardosilva/wireguard-webadmin-cluster-node|manual|./containers/cluster_node|Dockerfile-cluster_node"
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
  IFS="|" read -r SVC IMG FLAG CTX DOC <<< "$entry"
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
    IFS="|" read -r SVC IMG FLAG CTX DOC <<< "$entry"
    [ "$FLAG" != "manual" ] && SELECTED+=("$entry")
  done
else
  if ! echo "$img_choice" | grep -qE '^[0-9]+$'; then
    echo "Invalid choice." && exit 1
  fi
  idx=$((img_choice - 1))
  if [ "$idx" -lt 0 ] || [ "$idx" -ge "${#SERVICES[@]}" ]; then
    echo "Invalid choice." && exit 1
  fi
  SELECTED=("${SERVICES[$idx]}")
fi

# ── Confirm ──
echo ""
echo "$SEP"
echo "  Tag     : $TAG"
echo "  Default : linux/amd64,linux/arm64"
echo "  Images:"
for entry in "${SELECTED[@]}"; do
  IFS="|" read -r SVC IMG FLAG CTX DOC PLATFORMS <<< "$entry"
  if [ -n "$PLATFORMS" ]; then
    printf "    - %s:%s  [%s]\n" "$IMG" "$TAG" "$PLATFORMS"
  else
    printf "    - %s:%s\n" "$IMG" "$TAG"
  fi
done
echo "$SEP"
printf "Confirm? [y/N]: "
read confirm
case "$confirm" in
  [yY]*) ;;
  *) echo "Aborted." && exit 0 ;;
esac

# ── Setup QEMU + Buildx ──
echo ""
echo "$SEP"
echo "Removing existing buildx builder (if any)..."
docker buildx rm multi-builder 2>/dev/null || true

echo "$SEP"
echo "Pruning Docker system..."
docker system prune -a

echo "$SEP"
if [ "$(uname)" = "Linux" ]; then
  echo "Setting up QEMU for ARM emulation..."
  docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
  echo "$SEP"
  echo "Creating buildx builder..."
  docker buildx create --name multi-builder --use
else
  CURRENT_CONTEXT=$(docker context show)
  echo "macOS detected — using existing builder: $CURRENT_CONTEXT"
  docker buildx use "$CURRENT_CONTEXT"
fi

# ── .dockerignore ──
cat .gitignore > .dockerignore

# ── Build and push ──
DEFAULT_PLATFORMS="linux/amd64,linux/arm64"
echo ""
echo "$SEP"
echo "Building and pushing..."
for entry in "${SELECTED[@]}"; do
  IFS="|" read -r SVC IMG FLAG CTX DOC PLATFORMS <<< "$entry"
  FULL_IMAGE="$IMG:$TAG"
  BUILD_PLATFORMS="${PLATFORMS:-$DEFAULT_PLATFORMS}"

  echo ""
  echo "--- Building $FULL_IMAGE ($BUILD_PLATFORMS)..."

  if [ -z "$DOC" ]; then
    docker buildx build \
      --platform "$BUILD_PLATFORMS" \
      -t "$FULL_IMAGE" \
      --push \
      "$CTX"
  else
    docker buildx build \
      --platform "$BUILD_PLATFORMS" \
      -t "$FULL_IMAGE" \
      --push \
      -f "$CTX/$DOC" \
      "$CTX"
  fi

  if [ $? -ne 0 ]; then
    echo "ERROR building/pushing $FULL_IMAGE" && exit 1
  fi
  echo "--- $FULL_IMAGE built and pushed successfully."
done

echo ""
echo "$SEP"
echo "Done. Tag: $TAG"
