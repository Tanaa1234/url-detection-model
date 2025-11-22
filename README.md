# Enterprise URL Security Analyzer 🛡️

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Advanced AI-powered threat detection system achieving **90.4% accuracy** for identifying phishing, malware, and defacement attacks.

## 🚀 Features

- **Enhanced Classifier v4.0** - 90.4% accuracy with hybrid rule-based + ML approach
- **Multiple ML Models** - Random Forest, XGBoost, SVM, KNN, and Ensemble methods  
- **Professional UI** - Enterprise-grade Streamlit interface
- **Real-time Analysis** - Instant URL threat assessment
- **Multi-depth Analysis** - Quick Scan, Enterprise Grade, and Deep Analysis modes
- **Comprehensive Detection** - Phishing, malware, defacement, and suspicious hosting detection

## 🎯 Accuracy Performance

- **Enhanced Classifier v4.0**: 90.4% (123/136 correct)
- **Defacement Detection**: 100% (29/29)
- **Malware Detection**: 100% (3/3)  
- **Phishing Detection**: Highly accurate with suspicious hosting pattern recognition

## 🏗️ Project Structure

```
url-detection-model/
├── app_professional.py              # Main Streamlit application
├── enhanced_classifier_v4.py        # Enhanced Classifier v4.0 (90.4% accuracy)
├── test_enhanced_out_of_dataset.py  # Testing script
├── models/                          # Trained ML models
│   ├── enhanced_classifier.joblib
│   ├── feature_extractor.joblib
│   ├── random_forest_model.joblib
│   ├── xgboost_model.joblib
│   ├── svm_model.joblib
│   ├── knn_model.joblib
│   └── *_scaler.joblib
├── analysis/
│   └── results_v4_detailed.csv     # Latest accuracy results
├── data/                            # Training datasets
├── requirements.txt                 # Python dependencies
├── Dockerfile                       # Docker containerization
└── README.md                        # This file
```

## 🚀 Quick Start

### Local Installation

1. **Clone the repository**
```bash
git clone https://github.com/Tanaa1234/url-detection-model.git
cd url-detection-model
```

2. **Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the application**
```bash
streamlit run app_professional.py
```

5. **Open your browser**
Visit `http://localhost:8501` to access the Enterprise URL Security Analyzer

### Docker Installation

```bash
docker build -t url-security-analyzer .
docker run -p 8501:8501 url-security-analyzer
```

## 🎛️ Usage

1. **Select AI Model**: Choose from Enhanced Classifier v4.0, Random Forest, XGBoost, SVM, KNN, or Ensemble
2. **Analysis Depth**: Select Quick Scan, Enterprise Grade, or Deep Analysis
3. **Enter URL**: Input the URL you want to analyze
4. **Get Results**: View comprehensive threat analysis with confidence scores

## 🤖 Available Models

| Model | Accuracy | Specialty |
|-------|----------|-----------|
| Enhanced Classifier v4.0 | 90.4% | Hybrid rule-based + ML with pattern recognition |
| Random Forest | 75% | Tree-based ensemble learning |
| XGBoost | 73% | Gradient boosting framework |
| Support Vector Machine | 70% | Support vector classification |
| K-Nearest Neighbors | 68% | Instance-based learning |
| Ensemble | 85% | Multi-model consensus |

## 🔍 Detection Capabilities

### Threat Categories
- **Phishing**: Brand impersonation, credential harvesting
- **Malware**: Malicious downloads, infected sites
- **Defacement**: Compromised websites, CMS vulnerabilities
- **Suspicious Hosting**: Free hosting services, suspicious TLDs

### Analysis Depth Options
- **Quick Scan**: Rapid basic analysis (6 features)
- **Enterprise Grade**: Standard comprehensive analysis (10 features) 
- **Deep Analysis**: Full pattern analysis (13 features)

## 📊 Technical Details

### Enhanced Classifier v4.0 Features
- Aggressive defacement pattern detection
- Multi-language content analysis (Dutch, German, Italian, Spanish, etc.)
- Suspicious hosting service detection (.000webhostapp.com, etc.)
- High-risk TLD identification (.tk, .ml, .ga, .cf)
- Country-specific domain analysis
- CMS vulnerability pattern recognition

### Risk Assessment Levels
- **NO THREAT**: Verified legitimate sites
- **LOW RISK**: Minimal threat indicators
- **MODERATE RISK**: Some suspicious characteristics
- **HIGH RISK**: Multiple threat indicators
- **CRITICAL RISK**: Confirmed malicious patterns

## 🛠️ Development

### Testing
```bash
python test_enhanced_out_of_dataset.py
```

### Model Training
The Enhanced Classifier v4.0 uses a hybrid approach combining:
- Rule-based pattern matching
- Machine learning classification
- Threat intelligence correlation

## 📈 Performance Metrics

Based on comprehensive testing with 136 diverse URLs:
- **Overall Accuracy**: 90.4%
- **Precision**: High across all categories
- **Recall**: Excellent for defacement and malware
- **F1-Score**: Balanced performance

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

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Machine learning models trained on comprehensive URL datasets
- Streamlit for the professional web interface
- Various threat intelligence sources for pattern recognition

---

**Enterprise URL Security Analyzer** - Protecting your digital infrastructure with AI-powered threat detection.