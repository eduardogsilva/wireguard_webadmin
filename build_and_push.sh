#!/bin/bash

IMAGES=(
  "eduardosilva/wireguard_webadmin:latest"
  "eduardosilva/wireguard_webadmin_cron:latest"
  "eduardosilva/wireguard_webadmin_nginx:latest"
  "eduardosilva/wireguard_webadmin_dns:latest"
)

build_images() {
  echo "Starting the build of the images..."
  docker compose -f docker-compose-build.yml build
  if [ $? -eq 0 ]; then
    echo "Build completed successfully."
  else
    echo "Error during the image build."
    exit 1
  fi
}

push_images() {
  for IMAGE in "${IMAGES[@]}"; do
    echo "Pushing image: $IMAGE..."
    docker push "$IMAGE"
    if [ $? -eq 0 ]; then
      echo "$IMAGE pushed successfully."
    else
      echo "Error pushing the image: $IMAGE"
      exit 1
    fi
  done
}

docker system prune -a
build_images
push_images

echo "Build and push operations completed successfully."
