# URL Maliciousness Detection System - Deployment Guide

This repository contains a complete URL maliciousness detection system with multiple deployment options.

## 🚀 Quick Deploy

Run the automated deployment script:

```bash
./deploy_production.sh
```

## 📋 Deployment Options

### 1. Local Development
```bash
# Quick start
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

### 2. Docker Deployment
```bash
# Build and run
docker build -t url-detector .
docker run -p 8501:8501 url-detector

# Or use docker-compose
docker-compose up -d
```

### 3. Streamlit Cloud
1. Push repository to GitHub
2. Visit [share.streamlit.io](https://share.streamlit.io)
3. Connect GitHub repository
4. Set main file: `app.py`
5. Deploy!

### 4. Heroku Deployment
```bash
# Install Heroku CLI
heroku login
heroku create your-app-name
git push heroku main
```

### 5. AWS/Cloud Server
```bash
# On your server
git clone <your-repo>
cd url-detection-model
./deploy_production.sh
# Choose option 2 for production server
```

## 📁 Project Structure

```
url-detection-model/
├── app.py                     # Main Streamlit application
├── enhanced_classifier.py     # Enhanced classifier with rules
├── data_preprocessing.py      # Feature extraction
├── model_trainer.py          # ML model training
├── simple_trainer.py         # Streamlined training
├── requirements.txt          # Python dependencies
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Multi-container setup
├── Procfile                 # Heroku configuration
├── runtime.txt              # Python version for Heroku
├── .streamlit/              # Streamlit configuration
│   ├── config.toml
│   └── secrets.toml
├── deploy_production.sh     # Automated deployment
└── models/                  # Trained model files
    ├── enhanced_classifier.joblib
    ├── random_forest_model.joblib
    ├── xgboost_model.joblib
    └── feature_extractor.joblib
```

## 🔧 Configuration

### Environment Variables
```bash
ENVIRONMENT=production          # production/development
DEBUG_MODE=false               # true/false
MODEL_CACHE_DIR=./models       # Model files directory
```

### Streamlit Configuration
See `.streamlit/config.toml` for customization options.

## 📊 Model Performance

| Model | Accuracy | Training Time | Best Use Case |
|-------|----------|---------------|---------------|
| Enhanced Classifier | 99%+ | Instant | Recommended (rules + ML) |
| Random Forest | 99.09% | ~15 min | High accuracy |
| XGBoost | 99.19% | ~20 min | Best performance |
| KNN | 98.74% | ~10 min | Fast training |

## 🧪 Testing URLs

**Malicious Examples:**
- `https://paypaI.com/login` (typosquatting)
- `https://goog1e.com/search` (character substitution)
- `http://192.168.1.100/malware.exe` (IP address)

**Safe Examples:**
- `https://www.google.com`
- `https://github.com`
- `https://www.amazon.com`

## 🛡️ Security Features

- **Trusted Domain Override:** 80+ curated safe domains
- **Typosquatting Detection:** Catches domain impersonation
- **Pattern Recognition:** Gov/edu sites, CDNs, dev environments
- **Heuristic Analysis:** Suspicious domain characteristics
- **Out-of-dataset Generalization:** 90.91% accuracy on new URLs

## 🔍 Troubleshooting

### Common Issues

**Models not found:**
```bash
python simple_trainer.py  # Retrain models
```

**Import errors:**
```bash
pip install -r requirements.txt --upgrade
```

**Memory issues:**
```bash
# Reduce model complexity in model_trainer.py
# Or use smaller dataset sample
```

**Port already in use:**
```bash
# Kill existing processes
pkill -f streamlit
# Or use different port
streamlit run app.py --server.port 8502
```

### Docker Troubleshooting

**Build fails:**
```bash
docker system prune  # Clean Docker cache
docker build --no-cache -t url-detector .
```

**Container exits:**
```bash
docker logs <container_id>  # Check logs
```

### Streamlit Cloud Issues

**Build timeout:**
- Reduce model sizes
- Use model compression
- Consider lazy loading

**Memory limits:**
- Optimize feature extraction
- Use model quantization
- Implement model caching

## 📝 Customization

### Adding New Features
1. Update `data_preprocessing.py`
2. Retrain models with `simple_trainer.py`
3. Test with new URLs

### Modifying UI
1. Edit `app.py` Streamlit components
2. Customize `.streamlit/config.toml`
3. Add new visualizations

### Deployment Customization
1. Modify `Dockerfile` for custom base images
2. Update `requirements.txt` for new dependencies
3. Adjust `docker-compose.yml` for scaling

## 📚 API Usage

For programmatic access:

```python
from enhanced_classifier import EnhancedURLClassifier

classifier = EnhancedURLClassifier()
result = classifier.predict_url('https://example.com')
print(result)
# {'prediction': 'benign', 'confidence': 0.95, 'reason': 'Trusted domain override'}
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
- Check troubleshooting section above
- Review GitHub issues
- Enable debug mode in the app for detailed logs

---

**🎯 Ready to deploy? Run `./deploy_production.sh` and choose your preferred deployment method!**