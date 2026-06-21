#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: eng/release-container-publish.sh

Publishes the Docker api target to one configured OCI registry.

Required environment:
  REGISTRY_KIND              gitlab | generic | dockerhub | aws-ecr | github

Common optional environment:
  DOCKER_TARGET              Dockerfile target to build. Defaults to api.
  IMAGE_TAG                  Release tag. Defaults to CI_COMMIT_TAG.
  IMAGE_SHA_TAG              Short-SHA tag. Defaults to CI_COMMIT_SHORT_SHA.
  PUSH_LATEST_FOR_STABLE     true/false. Defaults to true.

GitLab registry:
  CI_REGISTRY
  CI_REGISTRY_IMAGE
  CI_REGISTRY_USER
  CI_REGISTRY_PASSWORD

Generic self-hosted registry:
  SELF_HOSTED_REGISTRY
  SELF_HOSTED_REGISTRY_IMAGE
  SELF_HOSTED_REGISTRY_USERNAME
  SELF_HOSTED_REGISTRY_PASSWORD

Docker Hub:
  DOCKERHUB_USERNAME
  DOCKERHUB_TOKEN
  DOCKERHUB_IMAGE

AWS ECR:
  AWS_REGION
  AWS_ACCOUNT_ID
  AWS_ECR_REPOSITORY or AWS_ECR_IMAGE
  AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE or runner-provided AWS credentials

GitHub Container Registry:
  GITHUB_CONTAINER_IMAGE    Full image name, for example ghcr.io/owner/repo
  GITHUB_TOKEN              Repository token with packages:write permission
  GITHUB_ACTOR              GitHub username that owns the token
  GITHUB_CONTAINER_REGISTRY Optional, defaults to ghcr.io
USAGE
}

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "Missing required environment variable: ${name}" >&2
    exit 2
  fi
}

stable_release_tag() {
  local tag="$1"
  printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

login_gitlab() {
  require_var CI_REGISTRY
  require_var CI_REGISTRY_IMAGE
  require_var CI_REGISTRY_USER
  require_var CI_REGISTRY_PASSWORD

  IMAGE_NAME="$CI_REGISTRY_IMAGE"
  echo "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY" --username "$CI_REGISTRY_USER" --password-stdin
}

login_generic() {
  require_var SELF_HOSTED_REGISTRY
  require_var SELF_HOSTED_REGISTRY_IMAGE
  require_var SELF_HOSTED_REGISTRY_USERNAME
  require_var SELF_HOSTED_REGISTRY_PASSWORD

  IMAGE_NAME="$SELF_HOSTED_REGISTRY_IMAGE"
  echo "$SELF_HOSTED_REGISTRY_PASSWORD" | docker login "$SELF_HOSTED_REGISTRY" --username "$SELF_HOSTED_REGISTRY_USERNAME" --password-stdin
}

login_dockerhub() {
  require_var DOCKERHUB_USERNAME
  require_var DOCKERHUB_TOKEN
  require_var DOCKERHUB_IMAGE

  IMAGE_NAME="$DOCKERHUB_IMAGE"
  echo "$DOCKERHUB_TOKEN" | docker login docker.io --username "$DOCKERHUB_USERNAME" --password-stdin
}

login_github() {
  GITHUB_CONTAINER_REGISTRY="${GITHUB_CONTAINER_REGISTRY:-ghcr.io}"
  require_var GITHUB_CONTAINER_IMAGE
  require_var GITHUB_TOKEN
  require_var GITHUB_ACTOR

  IMAGE_NAME="$GITHUB_CONTAINER_IMAGE"
  echo "$GITHUB_TOKEN" | docker login "$GITHUB_CONTAINER_REGISTRY" --username "$GITHUB_ACTOR" --password-stdin
}

login_aws_ecr() {
  require_var AWS_REGION
  require_var AWS_ACCOUNT_ID

  if [ -n "${AWS_ECR_IMAGE:-}" ]; then
    IMAGE_NAME="$AWS_ECR_IMAGE"
  else
    require_var AWS_ECR_REPOSITORY
    IMAGE_NAME="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${AWS_ECR_REPOSITORY}"
  fi

  aws ecr get-login-password --region "$AWS_REGION" \
    | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
}

publish_image() {
  local latest_tag="${IMAGE_NAME}:latest"
  local release_tag="${IMAGE_NAME}:${IMAGE_TAG}"
  local sha_tag="${IMAGE_NAME}:${IMAGE_SHA_TAG}"

  docker build --pull --target "$DOCKER_TARGET" --tag "$release_tag" --tag "$sha_tag" .

  if [ "$PUSH_LATEST_FOR_STABLE" = "true" ] && stable_release_tag "$IMAGE_TAG"; then
    docker tag "$release_tag" "$latest_tag"
  fi

  docker push "$release_tag"
  docker push "$sha_tag"

  if [ "$PUSH_LATEST_FOR_STABLE" = "true" ] && stable_release_tag "$IMAGE_TAG"; then
    docker push "$latest_tag"
  fi

  {
    echo "PUBLISHED_IMAGE=${release_tag}"
    echo "PUBLISHED_IMAGE_SHA_TAG=${sha_tag}"
    if [ "$PUSH_LATEST_FOR_STABLE" = "true" ] && stable_release_tag "$IMAGE_TAG"; then
      echo "PUBLISHED_IMAGE_LATEST_TAG=${latest_tag}"
    fi
  } > "${IMAGE_ENV_FILE:-image.env}"

  cat "${IMAGE_ENV_FILE:-image.env}"
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

require_var REGISTRY_KIND
DOCKER_TARGET="${DOCKER_TARGET:-api}"
IMAGE_TAG="${IMAGE_TAG:-${CI_COMMIT_TAG:-}}"
IMAGE_SHA_TAG="${IMAGE_SHA_TAG:-${CI_COMMIT_SHORT_SHA:-}}"
PUSH_LATEST_FOR_STABLE="${PUSH_LATEST_FOR_STABLE:-true}"

if [ -z "$IMAGE_TAG" ]; then
  echo "IMAGE_TAG or CI_COMMIT_TAG is required." >&2
  exit 2
fi

if [ -z "$IMAGE_SHA_TAG" ]; then
  echo "IMAGE_SHA_TAG or CI_COMMIT_SHORT_SHA is required." >&2
  exit 2
fi

case "$REGISTRY_KIND" in
  gitlab)
    login_gitlab
    ;;
  generic)
    login_generic
    ;;
  dockerhub)
    login_dockerhub
    ;;
  aws-ecr)
    login_aws_ecr
    ;;
  github|ghcr)
    login_github
    ;;
  *)
    echo "Unsupported REGISTRY_KIND: ${REGISTRY_KIND}" >&2
    usage >&2
    exit 2
    ;;
esac

publish_image
