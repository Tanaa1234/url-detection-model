"""
Quick improved training to fix false positives on legitimate URLs
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from sklearn.preprocessing import StandardScaler
import joblib
import os
from data_preprocessing import URLFeatureExtractor
import kagglehub

def quick_improved_training():
    """Quick training with better data balance to fix false positives"""
    print("🚀 QUICK IMPROVED TRAINING - Fixing False Positives")
    print("="*60)
    
    # Load dataset
    print("Loading dataset...")
    path = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
    df = pd.read_csv(f"{path}/malicious_phish.csv")
    
    # Create a better balanced sample with more benign URLs
    print("Creating balanced dataset with emphasis on legitimate URLs...")
    
    # Sample more benign URLs to reduce false positives
    benign_sample = df[df['type'] == 'benign'].sample(n=15000, random_state=42)
    phishing_sample = df[df['type'] == 'phishing'].sample(n=5000, random_state=42)
    malware_sample = df[df['type'] == 'malware'].sample(n=5000, random_state=42)
    defacement_sample = df[df['type'] == 'defacement'].sample(n=5000, random_state=42)
    
    # Combine samples
    balanced_df = pd.concat([benign_sample, phishing_sample, malware_sample, defacement_sample])
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Balanced dataset: {len(balanced_df)} URLs")
    print("Distribution:")
    print(balanced_df['type'].value_counts())
    
    # Extract features
    print("Extracting features...")
    extractor = URLFeatureExtractor()
    X_train, X_test, y_train, y_test, feature_names = extractor.prepare_data(balanced_df)
    
    # Train improved models
    print("Training improved models...")
    
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=4,
            class_weight='balanced_subsample',
            random_state=42
        ),
        'XGBoost': XGBClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='mlogloss'
        ),
        'KNN': KNeighborsClassifier(
            n_neighbors=9,
            weights='distance',
            metric='manhattan'
        ),
        'SVM': SVC(
            C=0.8,
            kernel='rbf',
            gamma='scale',
            class_weight='balanced',
            probability=True,
            random_state=42
        )
    }
    
    # Initialize scalers
    scalers = {}
    scalers['KNN'] = StandardScaler()
    scalers['SVM'] = StandardScaler()
    
    trained_models = {}
    results = {}
    
    for model_name, model in models.items():
        print(f"Training {model_name}...")
        
        # Scale data if needed
        X_train_processed = X_train.copy()
        X_test_processed = X_test.copy()
        
        if model_name in scalers:
            X_train_processed = scalers[model_name].fit_transform(X_train)
            X_test_processed = scalers[model_name].transform(X_test)
        
        # Train model
        model.fit(X_train_processed, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test_processed)
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        
        trained_models[model_name] = model
        results[model_name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1
        }
        
        print(f"{model_name} - Accuracy: {accuracy:.4f}, F1: {f1:.4f}")
    
    # Test on known good URLs
    print("\nTesting on known legitimate URLs...")
    test_urls = [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://www.amazon.com',
        'https://www.microsoft.com',
        'https://www.apple.com',
        'https://github.com',
        'https://stackoverflow.com',
        'https://www.wikipedia.org'
    ]
    
    for url in test_urls:
        url_features = extractor.transform_single_url(url)
        predictions = {}
        
        for model_name, model in trained_models.items():
            features_processed = url_features.copy()
            if model_name in scalers:
                features_processed = scalers[model_name].transform(features_processed)
            
            pred = model.predict(features_processed)[0]
            pred_proba = model.predict_proba(features_processed)[0]
            class_name = extractor.label_encoder.inverse_transform([pred])[0]
            
            predictions[model_name] = {
                'prediction': class_name,
                'confidence': max(pred_proba)
            }
        
        benign_votes = sum(1 for pred in predictions.values() if pred['prediction'] == 'benign')
        print(f"{url}: {benign_votes}/4 models predict 'benign'")
    
    # Save improved models
    print("\nSaving improved models...")
    os.makedirs('models', exist_ok=True)
    
    for model_name, model in trained_models.items():
        model_filename = f"models/{model_name.lower().replace(' ', '_')}_model.joblib"
        joblib.dump(model, model_filename)
        
        if model_name in scalers:
            scaler_filename = f"models/{model_name.lower().replace(' ', '_')}_scaler.joblib"
            joblib.dump(scalers[model_name], scaler_filename)
    
    joblib.dump(extractor, 'models/feature_extractor.joblib')
    joblib.dump(results, 'models/model_results.joblib')
    
    print("✅ Improved models saved!")
    print("\nModel Performance Summary:")
    for model_name, metrics in results.items():
        print(f"{model_name}: Accuracy={metrics['accuracy']:.4f}, F1={metrics['f1_score']:.4f}")
    
    print("\n🎉 Training complete! Models should now perform much better on legitimate URLs.")

if __name__ == "__main__":
    quick_improved_training()