#!/bin/bash

# AI-Powered Cybersecurity Platform - Quick Start Script
# This script helps you get the platform running quickly with Docker

set -e

echo "🔒 AI-Powered Cybersecurity Platform - Quick Start"
echo "=================================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "✅ Docker and Docker Compose are available"

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p backend/logs
mkdir -p data/uploads
mkdir -p data/models
mkdir -p nginx

# Create basic nginx config if it doesn't exist
if [ ! -f "nginx/nginx.conf" ]; then
    echo "🔧 Creating basic nginx configuration..."
    cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream backend {
        server backend:8000;
    }

    upstream frontend {
        server frontend:3000;
    }

    server {
        listen 80;
        server_name localhost;

        location /api/ {
            proxy_pass http://backend/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location / {
            proxy_pass http://frontend/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "🔧 Creating environment configuration..."
    cat > .env << 'EOF'
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=info

# Frontend Configuration
REACT_APP_API_URL=http://localhost:8000/api
NODE_ENV=development

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=cybersecurity_redis_pass

# ML Model Configuration
MODEL_CACHE_SIZE=1000
ENABLE_MODEL_RETRAINING=true
TRAINING_DATA_PATH=./data/training
EOF
fi

echo "🚀 Starting the AI Cybersecurity Platform..."

# Check if user wants development or production mode
echo ""
echo "Choose deployment mode:"
echo "1) Development (with hot reload)"
echo "2) Production (optimized)"
echo "3) Development with Nginx proxy"
read -p "Enter choice (1-3) [1]: " mode
mode=${mode:-1}

case $mode in
    1)
        echo "🔧 Starting in development mode..."
        docker-compose up -d redis
        docker-compose --profile dev up -d frontend-dev
        docker-compose up -d backend
        echo ""
        echo "✅ Platform is starting up!"
        echo "📊 Frontend: http://localhost:3001"
        echo "🔗 API: http://localhost:8000"
        echo "📚 API Docs: http://localhost:8000/docs"
        echo "💊 Redis: localhost:6379"
        ;;
    2)
        echo "🏭 Starting in production mode..."
        docker-compose up -d --build
        echo ""
        echo "✅ Platform is starting up!"
        echo "📊 Frontend: http://localhost:3000"
        echo "🔗 API: http://localhost:8000"
        echo "📚 API Docs: http://localhost:8000/docs"
        ;;
    3)
        echo "🔧 Starting with Nginx proxy..."
        docker-compose --profile production up -d --build
        echo ""
        echo "✅ Platform is starting up!"
        echo "🌐 Application: http://localhost"
        echo "📚 API Docs: http://localhost/docs"
        ;;
    *)
        echo "Invalid choice. Starting in development mode..."
        docker-compose --profile dev up -d
        ;;
esac

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if services are healthy
echo "🔍 Checking service health..."

# Check backend health
if curl -f -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ Backend is healthy"
else
    echo "⚠️  Backend is still starting up..."
fi

# Check redis
if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    echo "✅ Redis is healthy"
else
    echo "⚠️  Redis is still starting up..."
fi

echo ""
echo "📋 Platform Status:"
echo "=================="
docker-compose ps

echo ""
echo "📖 Useful Commands:"
echo "==================="
echo "• View logs:           docker-compose logs -f"
echo "• Stop platform:       docker-compose down"
echo "• Restart services:    docker-compose restart"
echo "• Update and rebuild:  docker-compose up -d --build"
echo "• Shell into backend:  docker-compose exec backend bash"
echo "• View Redis data:     docker-compose exec redis redis-cli"

echo ""
echo "🎉 AI Cybersecurity Platform is ready!"
echo "   Visit the application and start analyzing threats with AI!"

# Open browser if possible (macOS/Linux with GUI)
if command -v open &> /dev/null; then
    echo "🌐 Opening browser..."
    sleep 3
    open http://localhost:3000 2>/dev/null || open http://localhost 2>/dev/null
elif command -v xdg-open &> /dev/null; then
    echo "🌐 Opening browser..."
    sleep 3
    xdg-open http://localhost:3000 2>/dev/null || xdg-open http://localhost 2>/dev/null
fi