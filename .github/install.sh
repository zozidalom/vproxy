#!/bin/bash

# Fetch the latest release information
release_info=$(curl -s "https://api.github.com/repos/0x676e67/vproxy/releases/latest")
tag=$(echo $release_info | grep -oP '"tag_name": "\K(.*?)(?=")')
version=${tag#v}

# Get system architecture and OS
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Select the appropriate filename based on the system architecture and OS
case "$ARCH-$OS" in
    "aarch64-darwin") FILENAME="vproxy-$version-aarch64-apple-darwin.tar.gz" ;;
    "aarch64-linux") FILENAME="vproxy-$version-aarch64-unknown-linux-musl.tar.gz" ;;
    "arm-linux") FILENAME="vproxy-$version-arm-unknown-linux-musleabihf.tar.gz" ;;
    "armv7l-linux") FILENAME="vproxy-$version-armv7-unknown-linux-musleabihf.tar.gz" ;;
    "i686-windows") FILENAME="vproxy-$version-i686-pc-windows-gnu.tar.gz" ;;
    "i686-linux") FILENAME="vproxy-$version-i686-unknown-linux-musl.tar.gz" ;;
    "x86_64-darwin") FILENAME="vproxy-$version-x86_64-apple-darwin.tar.gz" ;;
    "x86_64-windows") FILENAME="vproxy-$version-x86_64-pc-windows-gnu.tar.gz" ;;
    "x86_64-linux") FILENAME="vproxy-$version-x86_64-unknown-linux-musl.tar.gz" ;;
    *) echo "Unknown system architecture: $ARCH-$OS"; exit 1 ;;
esac

# Construct the download URL
download_url="https://github.com/0x676e67/vproxy/releases/download/$tag/$FILENAME"

echo "Download URL: $download_url"

if [ -z "$download_url" ]; then
    echo "Could not find a suitable package for your system architecture."
    exit 1
fi

# Download the binary package
curl -L -o $FILENAME $download_url

echo "Download complete: $FILENAME"

# Extract the binary package
tar -xzf $FILENAME

echo "Extraction complete: $FILENAME"

# Ask the user if they want to automatically install the package
read -p "Do you want to install the package to /bin/vproxy? (y/n): " install_choice

if [ "$install_choice" = "y" ] || [ "$install_choice" = "Y" ]; then
    # Move the extracted files to the installation path
    # Assuming the binary file is named `vproxy`
    sudo mv vproxy /bin/vproxy

    echo "Installation complete: /bin/vproxy"
else
    echo "Installation skipped."
fi
