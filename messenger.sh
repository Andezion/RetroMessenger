#!/bin/bash

set -e  

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

if [ -f /.flatpak-info ]; then
    echo "Error: You're running this from VS Code's Flatpak terminal"
    echo "Please open a regular terminal (Ctrl+Alt+T) and run this script again"
    exit 1
fi

build() {
    echo "======================================"
    echo "Building RetroMessenger..."
    echo "======================================"
    
    rm -rf build
    mkdir build
    cd build
    
    cmake ..
    make -j$(nproc)
    
    echo ""
    echo "Build successful!"
    echo ""
}

run() {
    if [ ! -f "build/RetroMessenger" ]; then
        echo "Error: RetroMessenger not built yet"
        echo "Building first..."
        build
    fi
    
    echo "Starting RetroMessenger..."
    echo ""
    ./build/RetroMessenger
}

run_server() {
    if [ ! -f "build/ChatServer" ]; then
        echo "Error: ChatServer not built yet"
        echo "Building first..."
        build
    fi
    
    PORT=${1:-12345}
    echo "Starting ChatServer on port $PORT..."
    echo ""
    ./build/ChatServer $PORT
}

case "${1:-run}" in
    build)
        build
        ;;
    run)
        run
        ;;
    server)
        run_server "$2"
        ;;
    clean)
        echo "Cleaning build directory..."
        rm -rf build
        echo "Clean complete"
        ;;
    *)
        echo "RetroMessenger - Peer-to-Peer Messenger"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  build           - Build the project"
        echo "  run (default)   - Build and run the messenger"
        echo "  server [port]   - Run the optional server (default port: 12345)"
        echo "  clean           - Remove build directory"
        echo ""
        echo "Examples:"
        echo "  $0              # Build and run messenger"
        echo "  $0 build        # Just build"
        echo "  $0 server       # Run server on port 12345"
        echo "  $0 server 8080  # Run server on port 8080"
        exit 0
        ;;
esac
