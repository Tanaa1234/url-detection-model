# URL Maliciousness Detection System 🔍

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive machine learning application that detects malicious URLs using multiple algorithms including **Random Forest**, **XGBoost**, **K-Nearest Neighbors (KNN)**, and **Support Vector Machine (SVM)**.

## 🚀 Quick Start

### Option 1: Automatic Setup (Recommended)
```bash
./run.sh
```

### Option 2: Manual Setup

1. **Create and activate virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Train models and launch application:**
```bash
python main.py
```

### Option 3: Step-by-Step

1. **Train models only:**
```bash
python main.py --action train
```

2. **Launch web application:**
```bash
python main.py --action run
```

Or directly with Streamlit:
```bash
streamlit run app.py
```

## 📊 Dataset

The system uses the "Malicious URLs Dataset" from Kaggle containing 650K+ labeled URLs:
- **Benign**: 428,103 safe URLs
- **Defacement**: 96,457 defaced website URLs  
- **Phishing**: 94,111 phishing URLs
- **Malware**: 32,520 malware distribution URLs

## 🤖 Machine Learning Models

### Algorithms Used:
1. **Random Forest** - Ensemble method with multiple decision trees
2. **XGBoost** - Gradient boosting framework optimized for performance  
3. **K-Nearest Neighbors** - Instance-based learning algorithm
4. **Support Vector Machine** - Finds optimal decision boundaries

### Feature Engineering:
- **Basic Properties**: URL length, domain length, path depth
- **Character Analysis**: Digit/letter ratios, special characters  
- **Security Indicators**: HTTPS usage, IP addresses, suspicious TLDs
- **Entropy Measures**: Randomness analysis of URLs and domains
- **Pattern Detection**: URL shorteners, suspicious patterns

## 🌐 Web Interface Features

### Single URL Analysis
- Real-time URL classification
- Confidence scores from all models
- Detailed feature analysis
- Risk assessment with visual indicators

### Batch Processing  
- CSV file upload support
- Multiple URL analysis
- Downloadable results
- Progress tracking

### Model Performance Dashboard
- Accuracy, Precision, Recall, F1-Score metrics
- Comparative visualizations
- Detailed performance breakdowns

## 📁 Project Structure

```
url-detection-model/
├── app.py                 # Streamlit web interface
├── main.py               # Main application orchestrator  
├── model_trainer.py      # ML model training & evaluation
├── data_preprocessing.py # Feature extraction & data processing
├── dataset_downloader.py # Kaggle dataset downloader
├── requirements.txt      # Python dependencies
├── run.sh               # Quick start script
├── README.md           # This file
├── models/             # Trained model storage
│   ├── random_forest_model.joblib
│   ├── xgboost_model.joblib  
│   ├── knn_model.joblib
│   ├── svm_model.joblib
│   └── feature_extractor.joblib
└── data/              # Dataset storage
```

## ⚙️ Configuration Options

### Training Parameters
- `--sample-size`: Number of samples for training (default: 50,000)
- Grid search hyperparameter optimization available
- Cross-validation for model evaluation

### Model Features (35+ features extracted)
- URL structural properties
- Domain and subdomain analysis  
- Character composition metrics
- Security and trust indicators
- Entropy and randomness measures

## 📈 Performance

Typical performance metrics on test data:
- **Accuracy**: 95%+ across all models
- **Precision**: High precision for malicious URL detection
- **Recall**: Balanced recall across all threat categories
- **F1-Score**: Optimized for real-world deployment

## 🔧 Usage Examples

### Python API Usage
```python
from model_trainer import URLClassifierTrainer

# Load trained models
trainer = URLClassifierTrainer()
trainer.load_models('models')

# Predict single URL
predictions = trainer.predict_url('https://suspicious-site.com')
print(predictions)
```

### Command Line Usage
```bash
# Train with custom sample size
python main.py --action train --sample-size 100000

# Launch application only
python main.py --action run

# Full pipeline
python main.py --action both
```

## 🛡️ Security Notes

- This tool provides risk assessment, not definitive security guarantees
- Always use in conjunction with other security measures
- Regular model retraining recommended for optimal performance
- Consider false positive rates in production deployments

## 🔄 Updates & Maintenance

### Retraining Models
```bash
# Delete existing models to force retraining
rm -rf models/
python main.py --action train
```

### Adding New Features
1. Modify `URLFeatureExtractor` in `data_preprocessing.py`
2. Retrain models with updated features
3. Test performance improvements

## 📋 Requirements

- Python 3.7+
- 4GB+ RAM (for full dataset training)
- Internet connection (for dataset download)
- Web browser (for Streamlit interface)

## 🐛 Troubleshooting

### Common Issues:
1. **Import errors**: Ensure virtual environment is activated
2. **Memory errors**: Reduce sample size for training
3. **Slow training**: Use smaller sample or disable grid search
4. **Streamlit errors**: Check port 8501 availability

### Getting Help:
- Check the console output for detailed error messages
- Verify all dependencies are installed correctly
- Ensure adequate system resources for training

## 📝 License

This project is for educational and research purposes. Please respect the Kaggle dataset license terms.

---

**Built with ❤️ using Python, Scikit-learn, XGBoost, and Streamlit**