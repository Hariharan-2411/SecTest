#!/bin/bash

# SecTest Pro - Validation Test Script
# This script helps validate the extension against test targets

echo "🔒 SecTest Pro - Validation Test Script"
echo "========================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker to run test targets."
    exit 1
fi

echo "✓ Docker found"
echo ""

# Function to start DVWA
start_dvwa() {
    echo "🚀 Starting DVWA (Damn Vulnerable Web Application)..."
    docker run -d --name dvwa-test -p 8080:80 vulnerables/web-dvwa
    if [ $? -eq 0 ]; then
        echo "✅ DVWA started successfully on http://localhost:8080"
        echo "   Default credentials: admin/password"
    else
        echo "❌ Failed to start DVWA"
    fi
}

# Function to start WebGoat
start_webgoat() {
    echo "🚀 Starting WebGoat..."
    docker run -d --name webgoat-test -p 8081:8080 -p 9090:9090 webgoat/webgoat
    if [ $? -eq 0 ]; then
        echo "✅ WebGoat started successfully on http://localhost:8081/WebGoat"
    else
        echo "❌ Failed to start WebGoat"
    fi
}

# Function to start Juice Shop
start_juiceshop() {
    echo "🚀 Starting OWASP Juice Shop..."
    docker run -d --name juiceshop-test -p 3000:3000 bkimminich/juice-shop
    if [ $? -eq 0 ]; then
        echo "✅ Juice Shop started successfully on http://localhost:3000"
    else
        echo "❌ Failed to start Juice Shop"
    fi
}

# Function to stop all test containers
stop_all() {
    echo "🛑 Stopping all test containers..."
    docker stop dvwa-test webgoat-test juiceshop-test 2>/dev/null
    docker rm dvwa-test webgoat-test juiceshop-test 2>/dev/null
    echo "✅ All test containers stopped"
}

# Function to show status
show_status() {
    echo "📊 Test Container Status:"
    echo ""
    docker ps --filter "name=dvwa-test" --filter "name=webgoat-test" --filter "name=juiceshop-test" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

# Main menu
case "${1:-}" in
    dvwa)
        start_dvwa
        ;;
    webgoat)
        start_webgoat
        ;;
    juiceshop)
        start_juiceshop
        ;;
    all)
        start_dvwa
        echo ""
        start_webgoat
        echo ""
        start_juiceshop
        echo ""
        echo "🎯 All test targets started!"
        ;;
    stop)
        stop_all
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {dvwa|webgoat|juiceshop|all|stop|status}"
        echo ""
        echo "Commands:"
        echo "  dvwa       - Start DVWA on port 8080"
        echo "  webgoat    - Start WebGoat on port 8081"
        echo "  juiceshop  - Start Juice Shop on port 3000"
        echo "  all        - Start all test targets"
        echo "  stop       - Stop all test containers"
        echo "  status     - Show running test containers"
        echo ""
        echo "After starting targets:"
        echo "1. Load the extension in Chrome (chrome://extensions)"
        echo "2. Navigate to the test target URL"
        echo "3. Add 'localhost' to the allowlist in extension settings"
        echo "4. Click 'Scan Page' to enumerate forms"
        echo "5. Test actions with Dry Run mode first"
        echo "6. Export audit log when complete"
        exit 1
        ;;
esac

echo ""
echo "📝 Next Steps:"
echo "1. Open Chrome and navigate to chrome://extensions/"
echo "2. Enable Developer Mode"
echo "3. Click 'Load unpacked' and select the 'build' directory"
echo "4. Navigate to your test target"
echo "5. Click the SecTest Pro extension icon"
echo "6. Add the target host to allowlist in Settings"
echo "7. Start scanning and testing!"
