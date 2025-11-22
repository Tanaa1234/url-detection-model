#!/bin/bash

# URL Detection Model - Production Deployment Script
set -e

echo "🚀 Starting URL Detection Model Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required files exist
check_requirements() {
    print_status "Checking deployment requirements..."
    
    required_files=("app.py" "requirements.txt" "enhanced_classifier.joblib")
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            print_error "Required file $file not found!"
            exit 1
        fi
    done
    
    print_status "All required files found ✓"
}

# Check Python version
check_python() {
    print_status "Checking Python version..."
    
    python_version=$(python --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
    required_version="3.8"
    
    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
        print_error "Python $required_version or higher is required. Found: $python_version"
        exit 1
    fi
    
    print_status "Python version $python_version ✓"
}

# Setup virtual environment
setup_venv() {
    print_status "Setting up virtual environment..."
    
    if [ ! -d "venv" ]; then
        python -m venv venv
        print_status "Virtual environment created"
    else
        print_warning "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    print_status "Virtual environment ready ✓"
}

# Install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    pip install -r requirements.txt
    
    print_status "Dependencies installed ✓"
}

# Check model files
check_models() {
    print_status "Checking model files..."
    
    model_files=("enhanced_classifier.joblib" "random_forest_model.joblib" "xgboost_model.joblib")
    
    for model in "${model_files[@]}"; do
        if [ -f "$model" ]; then
            size=$(du -h "$model" | cut -f1)
            print_status "Found $model ($size)"
        else
            print_warning "$model not found - may need to train models"
        fi
    done
}

# Run health check
health_check() {
    print_status "Running application health check..."
    
    # Start Streamlit in background
    streamlit run app.py --server.headless=true --server.port=8502 &
    STREAMLIT_PID=$!
    
    # Wait for startup
    sleep 10
    
    # Check if process is running
    if kill -0 $STREAMLIT_PID 2>/dev/null; then
        print_status "Application started successfully ✓"
        
        # Test health endpoint
        if curl -f http://localhost:8502/_stcore/health >/dev/null 2>&1; then
            print_status "Health check passed ✓"
        else
            print_warning "Health endpoint not responding (this might be normal)"
        fi
        
        # Stop test instance
        kill $STREAMLIT_PID
        wait $STREAMLIT_PID 2>/dev/null || true
    else
        print_error "Application failed to start"
        exit 1
    fi
}

# Main deployment function
deploy() {
    echo "=========================================="
    echo "  URL Detection System Deployment"
    echo "=========================================="
    echo
    
    check_requirements
    check_python
    setup_venv
    install_dependencies
    check_models
    health_check
    
    echo
    print_status "🎉 Deployment completed successfully!"
    echo
    echo "To start the application:"
    echo "  source venv/bin/activate"
    echo "  streamlit run app.py"
    echo
    echo "Or use Docker:"
    echo "  docker-compose up -d"
    echo
    echo "For production deployment:"
    echo "  - Streamlit Cloud: Push to GitHub and connect repository"
    echo "  - Heroku: git push heroku main"
    echo "  - Docker: docker-compose -f docker-compose.prod.yml up -d"
    echo
}

# Handle command line arguments
case "${1:-deploy}" in
    "check")
        check_requirements
        check_python
        check_models
        ;;
    "install")
        setup_venv
        install_dependencies
        ;;
    "test")
        health_check
        ;;
    "deploy"|"")
        deploy
        ;;
    *)
        echo "Usage: $0 [check|install|test|deploy]"
        echo "  check   - Check requirements only"
        echo "  install - Install dependencies only" 
        echo "  test    - Run health check only"
        echo "  deploy  - Full deployment (default)"
        exit 1
        ;;
esac