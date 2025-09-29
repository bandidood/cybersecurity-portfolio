@echo off
setlocal enabledelayedexpansion

REM AI-Powered Cybersecurity Platform - Quick Start Script (Windows)
REM This script helps you get the platform running quickly with Docker

echo 🔒 AI-Powered Cybersecurity Platform - Quick Start
echo ==================================================

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    echo    Visit: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose is not installed. Please install Docker Desktop first.
    echo    Visit: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

echo ✅ Docker and Docker Compose are available

REM Create necessary directories
echo 📁 Creating necessary directories...
if not exist "backend\logs" mkdir backend\logs
if not exist "data\uploads" mkdir data\uploads
if not exist "data\models" mkdir data\models
if not exist "nginx" mkdir nginx

REM Create basic nginx config if it doesn't exist
if not exist "nginx\nginx.conf" (
    echo 🔧 Creating basic nginx configuration...
    (
        echo events {
        echo     worker_connections 1024;
        echo }
        echo.
        echo http {
        echo     upstream backend {
        echo         server backend:8000;
        echo     }
        echo.
        echo     upstream frontend {
        echo         server frontend:3000;
        echo     }
        echo.
        echo     server {
        echo         listen 80;
        echo         server_name localhost;
        echo.
        echo         location /api/ {
        echo             proxy_pass http://backend/;
        echo             proxy_set_header Host $host;
        echo             proxy_set_header X-Real-IP $remote_addr;
        echo             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        echo             proxy_set_header X-Forwarded-Proto $scheme;
        echo         }
        echo.
        echo         location / {
        echo             proxy_pass http://frontend/;
        echo             proxy_set_header Host $host;
        echo             proxy_set_header X-Real-IP $remote_addr;
        echo             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        echo             proxy_set_header X-Forwarded-Proto $scheme;
        echo         }
        echo     }
        echo }
    ) > nginx\nginx.conf
)

REM Create .env file if it doesn't exist
if not exist ".env" (
    echo 🔧 Creating environment configuration...
    (
        echo # API Configuration
        echo API_HOST=0.0.0.0
        echo API_PORT=8000
        echo LOG_LEVEL=info
        echo.
        echo # Frontend Configuration
        echo REACT_APP_API_URL=http://localhost:8000/api
        echo NODE_ENV=development
        echo.
        echo # Redis Configuration
        echo REDIS_HOST=redis
        echo REDIS_PORT=6379
        echo REDIS_PASSWORD=cybersecurity_redis_pass
        echo.
        echo # ML Model Configuration
        echo MODEL_CACHE_SIZE=1000
        echo ENABLE_MODEL_RETRAINING=true
        echo TRAINING_DATA_PATH=./data/training
    ) > .env
)

echo 🚀 Starting the AI Cybersecurity Platform...
echo.
echo Choose deployment mode:
echo 1) Development (with hot reload)
echo 2) Production (optimized)
echo 3) Development with Nginx proxy

set /p mode="Enter choice (1-3) [1]: "
if "%mode%"=="" set mode=1

if "%mode%"=="1" (
    echo 🔧 Starting in development mode...
    docker-compose up -d redis
    docker-compose --profile dev up -d frontend-dev
    docker-compose up -d backend
    echo.
    echo ✅ Platform is starting up!
    echo 📊 Frontend: http://localhost:3001
    echo 🔗 API: http://localhost:8000
    echo 📚 API Docs: http://localhost:8000/docs
    echo 💊 Redis: localhost:6379
) else if "%mode%"=="2" (
    echo 🏭 Starting in production mode...
    docker-compose up -d --build
    echo.
    echo ✅ Platform is starting up!
    echo 📊 Frontend: http://localhost:3000
    echo 🔗 API: http://localhost:8000
    echo 📚 API Docs: http://localhost:8000/docs
) else if "%mode%"=="3" (
    echo 🔧 Starting with Nginx proxy...
    docker-compose --profile production up -d --build
    echo.
    echo ✅ Platform is starting up!
    echo 🌐 Application: http://localhost
    echo 📚 API Docs: http://localhost/docs
) else (
    echo Invalid choice. Starting in development mode...
    docker-compose --profile dev up -d
)

echo.
echo ⏳ Waiting for services to be ready...
timeout /t 10 /nobreak >nul

REM Check if services are healthy
echo 🔍 Checking service health...

REM Check backend health
curl -f -s http://localhost:8000/health >nul 2>&1
if not errorlevel 1 (
    echo ✅ Backend is healthy
) else (
    echo ⚠️ Backend is still starting up...
)

echo.
echo 📋 Platform Status:
echo ==================
docker-compose ps

echo.
echo 📖 Useful Commands:
echo ===================
echo • View logs:           docker-compose logs -f
echo • Stop platform:       docker-compose down
echo • Restart services:    docker-compose restart
echo • Update and rebuild:  docker-compose up -d --build
echo • Shell into backend:  docker-compose exec backend bash
echo • View Redis data:     docker-compose exec redis redis-cli

echo.
echo 🎉 AI Cybersecurity Platform is ready!
echo    Visit the application and start analyzing threats with AI!

REM Open browser
echo 🌐 Opening browser...
timeout /t 3 /nobreak >nul
if "%mode%"=="1" (
    start http://localhost:3001
) else if "%mode%"=="3" (
    start http://localhost
) else (
    start http://localhost:3000
)

pause