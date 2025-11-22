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

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.8+ to continue."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    print_status "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip

# Install requirements
print_status "Installing dependencies..."
pip install -r requirements.txt

# Check if models exist, if not, train them
if [ ! -f "enhanced_classifier.joblib" ] || [ ! -f "random_forest_model.joblib" ]; then
    print_warning "Models not found. Training models..."
    
    # Download datasets if they don't exist
    if [ ! -d "data" ]; then
        print_status "Downloading datasets..."
        mkdir -p data
        python dataset_downloader.py
    fi
    
    # Train models
    print_status "Training ML models (this may take 15-30 minutes)..."
    python simple_trainer.py
    
    # Create enhanced classifier
    print_status "Creating enhanced classifier..."
    python -c "
import joblib
from enhanced_classifier import EnhancedURLClassifier
enhanced = EnhancedURLClassifier()
joblib.dump(enhanced, 'enhanced_classifier.joblib')
print('✅ Enhanced classifier created successfully!')
"
fi

# Validate models
print_status "Validating models..."
python -c "
import joblib
import os

models_to_check = [
    'enhanced_classifier.joblib',
    'random_forest_model.joblib', 
    'xgboost_model.joblib',
    'knn_model.joblib',
    'feature_extractor.joblib'
]

missing_models = []
for model in models_to_check:
    if not os.path.exists(model):
        missing_models.append(model)

if missing_models:
    print(f'❌ Missing models: {missing_models}')
    exit(1)
else:
    print('✅ All models validated successfully!')
"

# Set environment variables for production
export ENVIRONMENT=production
export DEBUG_MODE=false

# Choose deployment method
echo ""
echo "🎯 Choose deployment method:"
echo "1) Local development server"
echo "2) Production server (Streamlit)"
echo "3) Docker deployment"
echo "4) Streamlit Cloud deployment setup"
echo "5) Heroku deployment setup"

read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        print_status "Starting development server..."
        streamlit run app.py --server.port 8501 --server.address 0.0.0.0
        ;;
    2)
        print_status "Starting production server..."
        streamlit run app.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
        ;;
    3)
        print_status "Building Docker image..."
        if command -v docker &> /dev/null; then
            docker build -t url-detector .
            print_status "Starting Docker container..."
            docker run -p 8501:8501 url-detector
        else
            print_error "Docker is not installed. Please install Docker to use this option."
            exit 1
        fi
        ;;
    4)
        print_status "Setting up Streamlit Cloud deployment..."
        echo ""
        print_status "Streamlit Cloud deployment checklist:"
        echo "✅ requirements.txt is ready"
        echo "✅ app.py is the main application file"
        echo "✅ Enhanced classifier and models are created"
        echo ""
        print_warning "Next steps for Streamlit Cloud:"
        echo "1. Push this repository to GitHub"
        echo "2. Go to https://share.streamlit.io"
        echo "3. Connect your GitHub repository"
        echo "4. Set main file path to: app.py"
        echo "5. Deploy!"
        echo ""
        echo "🔗 Repository structure is ready for Streamlit Cloud deployment!"
        ;;
    5)
        print_status "Setting up Heroku deployment..."
        echo ""
        print_warning "Next steps for Heroku:"
        echo "1. Install Heroku CLI: https://devcenter.heroku.com/articles/heroku-cli"
        echo "2. Login: heroku login"
        echo "3. Create app: heroku create your-app-name"
        echo "4. Deploy: git push heroku main"
        echo ""
        print_status "Heroku configuration files are ready!"
        ;;
    *)
        print_error "Invalid choice. Please run the script again and choose 1-5."
        exit 1
        ;;
esac

print_status "Deployment completed successfully! 🎉"