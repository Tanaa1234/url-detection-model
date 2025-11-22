"""
Main application file for URL Detection System
"""

import os
import sys
import argparse
from model_trainer import main as train_models
import subprocess

def setup_environment():
    """Setup and verify the environment"""
    print("Setting up URL Detection System...")
    
    # Check if virtual environment is activated
    if sys.prefix == sys.base_prefix:
        print("Virtual environment not detected. Please activate it first:")
        print("source venv/bin/activate")
        return False
    
    print("✓ Virtual environment detected")
    
    # Check required directories
    if not os.path.exists('models'):
        os.makedirs('models')
        print("✓ Created models directory")
    
    if not os.path.exists('data'):
        os.makedirs('data')
        print("✓ Created data directory")
    
    return True

def train_system():
    """Train the ML models"""
    print("\n" + "="*50)
    print("TRAINING MACHINE LEARNING MODELS")
    print("="*50)
    print("This may take several minutes depending on your system...")
    print("Training with Random Forest, XGBoost, KNN, and SVM models")
    
    try:
        train_models()
        print("\n✓ Model training completed successfully!")
        return True
    except Exception as e:
        print(f"\n✗ Error during training: {e}")
        return False

def launch_app():
    """Launch the Streamlit application"""
    print("\n" + "="*50)
    print("LAUNCHING URL DETECTION WEB APPLICATION")
    print("="*50)
    print("Starting Streamlit server...")
    print("The application will open in your default browser.")
    print("Press Ctrl+C to stop the application.")
    
    try:
        subprocess.run(["streamlit", "run", "app.py"])
    except KeyboardInterrupt:
        print("\n\nApplication stopped by user.")
    except Exception as e:
        print(f"Error launching application: {e}")

def main():
    parser = argparse.ArgumentParser(description="URL Maliciousness Detection System")
    parser.add_argument("--action", choices=["train", "run", "both"], default="both",
                       help="Action to perform: train models, run app, or both (default: both)")
    parser.add_argument("--sample-size", type=int, default=50000,
                       help="Number of samples to use for training (default: 50000)")
    
    args = parser.parse_args()
    
    # Setup environment
    if not setup_environment():
        return
    
    # Check if models exist
    models_exist = (
        os.path.exists('models/random_forest_model.joblib') and
        os.path.exists('models/xgboost_model.joblib') and
        os.path.exists('models/knn_model.joblib') and
        os.path.exists('models/svm_model.joblib')
    )
    
    if args.action == "train" or (args.action == "both" and not models_exist):
        success = train_system()
        if not success and args.action == "both":
            print("Training failed. Cannot launch application without trained models.")
            return
    
    if args.action == "run" or args.action == "both":
        if not models_exist and args.action == "run":
            print("No trained models found. Please run training first:")
            print("python main.py --action train")
            return
        
        launch_app()

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║            URL MALICIOUSNESS DETECTION SYSTEM                ║
║                                                              ║
║  A Machine Learning Application for Detecting Malicious URLs ║
║                                                              ║
║  Models: Random Forest | XGBoost | KNN | SVM                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    main()