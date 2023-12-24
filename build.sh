#!/bin/bash

: ${os=linux}

# Function to print colored text based on log level
log() {
  local level=$1
  local message=$2
  local NC='\033[0m' # Reset to default color

  case "$level" in
    "info")
      echo -e "\033[0;32m[INFO] $message${NC}" # Green for INFO
      ;;
    "warning")
      echo -e "\033[0;33m[WARNING] $message${NC}" # Yellow for WARNING
      ;;
    "error")
      echo -e "\033[0;31m[ERROR] $message${NC}" # Red for ERROR
      ;;
    *)
      echo "$message" # Default to printing message without color for other levels
      ;;
  esac
}

# Build support paltform target
# 1. Linux (force musl)
linux_target=(
    "x86_64-unknown-linux-musl:mimalloc"
    "aarch64-unknown-linux-musl:mimalloc"
    "armv7-unknown-linux-musleabihf:mimalloc"
    "armv7-unknown-linux-musleabi:jemalloc"
    "arm-unknown-linux-musleabihf:jemalloc"
    "i686-unknown-linux-musl:jemalloc"
    "i586-unknown-linux-musl:jemalloc"
)

# 2. MacOS
macos_target=(
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
)

# 3. Windows
windows_target=(
    "x86_64-pc-windows-gnu"
    "i686-pc-windows-gnu"
)

# Check linux rustup target installed
check_linux_rustup_target_installed() {
    for target in ${linux_target[@]}; do
        target=$(echo $target | cut -d':' -f1)
        installed=$(rustup target list | grep "${target} (installed)")
        if [ -z "$installed" ]; then
            log "info" "Installing ${target}..."
            rustup target add ${target}
        fi
    done
}

# Check macos rustup target installed
check_macos_rustup_target_installed() {
    for target in ${macos_target[@]}; do
        installed=$(rustup target list | grep "${target} (installed)")
        if [ -z "$installed" ]; then
            log "info" "Installing ${target}..."
            rustup target add ${target}
        fi
    done
}

# Check windows rustup target installed
check_windows_rustup_target_installed() {
    for target in ${windows_target[@]}; do
        installed=$(rustup target list | grep "${target} (installed)")
        if [ -z "$installed" ]; then
            log "info" "Installing ${target}..."
            rustup target add ${target}
        fi
    done
}

# Build linux target
build_linux_target() {
  for target in "${linux_target[@]}"; do
    build_target=$(echo $target | cut -d':' -f1)
    feature=$(echo $target | cut -d':' -f2)
    log "info" "Building ${target}..."
    if cargo zigbuild --release --target "${build_target}" --features "${feature}"; then
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# Build macos target
build_macos_target() {
  for target in "${macos_target[@]}"; do
    log "info" "Building ${target}..."
    if CARGO_PROFILE_RELEASE_STRIP=none cargo zigbuild --release --target "${target}"; then
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# Build windows target
build_windows_target() {
  for target in "${windows_target[@]}"; do
    log "info" "Building ${target}..."
    if cargo build --release --target "${target}"; then
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# Execute
if [ "$os" == "linux" ]; then
  log "info" "Building linux target..."
  check_linux_rustup_target_installed
  build_linux_target
elif [ "$os" == "macos" ]; then
  log "info" "Building macos target..."
  check_macos_rustup_target_installed
  build_macos_target
elif [ "$os" == "windows" ]; then
  log "info" "Building windows target..."
  check_windows_rustup_target_installed
  build_windows_target
else
  log "error" "Unsupported os: ${os}"
  exit 1
fi
