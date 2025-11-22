#!/usr/bin/env python3
"""
Simple Multi-Dataset Trainer using existing infrastructure
"""

import os
import pandas as pd
import numpy as np
import kagglehub
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
import joblib
from data_preprocessing import URLFeatureExtractor
from enhanced_classifier import EnhancedURLClassifier
import warnings
warnings.filterwarnings('ignore')

def download_and_combine_datasets():
    """Download and combine both datasets"""
    print("📦 Downloading datasets...")
    
    # Dataset 1: Original
    path1 = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
    df1 = pd.read_csv(os.path.join(path1, 'malicious_phish.csv'))
    df1['label'] = df1['type'].apply(lambda x: 'benign' if x == 'benign' else 'malicious')
    df1 = df1[['url', 'label']].copy()
    
    # Dataset 2: Balanced
    path2 = kagglehub.dataset_download("samahsadiq/benign-and-malicious-urls") 
    df2 = pd.read_csv(os.path.join(path2, 'balanced_urls.csv'))
    df2 = df2[['url', 'label']].copy()
    
    # Combine
    combined_df = pd.concat([df1, df2], ignore_index=True)
    combined_df = combined_df.drop_duplicates(subset=['url'], keep='first')
    
    print(f"Combined dataset: {len(combined_df)} URLs")
    print("Label distribution:", combined_df['label'].value_counts().to_dict())
    
    return combined_df

def prepare_training_data(df, sample_size=50000):
    """Prepare data using existing URLFeatureExtractor"""
    print(f"🔄 Preparing training data (sampling {sample_size} URLs)...")
    
    # Sample for faster training
    if len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)
    
    # Clean data
    df = df.dropna()
    df = df[df['url'].str.contains(r'^https?://', na=False)]
    df = df[df['url'].str.len() < 2000]
    df = df[df['label'].isin(['benign', 'malicious'])]
    
    print(f"Cleaned dataset: {len(df)} URLs")
    
    # Use existing feature extraction method  
    extractor = URLFeatureExtractor()
    
    # Extract features using the existing method
    features_data = []
    labels = []
    
    print("Extracting features...")
    for idx, row in df.iterrows():
        if idx % 1000 == 0:
            print(f"Processed {idx}/{len(df)} URLs")
        
        try:
            features = extractor.extract_url_features(row['url'])
            # Convert to DataFrame row format that the extractor expects
            features_df = pd.DataFrame([features])
            features_data.append(features_df)
            labels.append(row['label'])
        except Exception as e:
            print(f"Error processing URL {row['url']}: {e}")
            continue
    
    # Combine all features
    print("Combining feature data...")
    if features_data:
        X_df = pd.concat(features_data, ignore_index=True)
        y = np.array(labels)
        
        # Ensure all features are numeric
        for col in X_df.columns:
            X_df[col] = pd.to_numeric(X_df[col], errors='coerce')
        X_df = X_df.fillna(0)
        
        X = X_df.values
        
        print(f"Final dataset shape: {X.shape}")
        print(f"Labels shape: {y.shape}")
        
        return X, y, extractor
    else:
        raise ValueError("No features extracted successfully")

def train_models_simple(X, y):
    """Train models with the prepared data"""
    print("🤖 Training models...")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Convert labels to binary
    y_train_binary = (y_train == 'malicious').astype(int)
    y_test_binary = (y_test == 'malicious').astype(int)
    
    models = {}
    scalers = {}
    
    # Random Forest
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train_binary)
    models['random_forest'] = rf
    
    # XGBoost  
    print("Training XGBoost...")
    xgb_model = xgb.XGBClassifier(n_estimators=100, max_depth=8, learning_rate=0.1, random_state=42, n_jobs=-1)
    xgb_model.fit(X_train, y_train_binary)
    models['xgboost'] = xgb_model
    
    # KNN (with scaling)
    print("Training KNN...")
    scaler_knn = StandardScaler()
    X_train_scaled_knn = scaler_knn.fit_transform(X_train)
    X_test_scaled_knn = scaler_knn.transform(X_test)
    knn = KNeighborsClassifier(n_neighbors=5, weights='distance', n_jobs=-1)
    knn.fit(X_train_scaled_knn, y_train_binary)
    models['knn'] = knn
    scalers['knn'] = scaler_knn
    
    # SVM (with scaling)
    print("Training SVM...")
    scaler_svm = StandardScaler()
    X_train_scaled_svm = scaler_svm.fit_transform(X_train)
    X_test_scaled_svm = scaler_svm.transform(X_test)
    svm = SVC(C=1.0, kernel='rbf', probability=True, random_state=42)
    svm.fit(X_train_scaled_svm, y_train_binary)
    models['svm'] = svm
    scalers['svm'] = scaler_svm
    
    # Evaluate models
    print("\\n📊 Model Evaluation:")
    for name, model in models.items():
        if name in scalers:
            X_test_eval = scalers[name].transform(X_test)
        else:
            X_test_eval = X_test
        
        y_pred = model.predict(X_test_eval)
        accuracy = accuracy_score(y_test_binary, y_pred)
        print(f"{name.upper()}: {accuracy:.4f} accuracy")
    
    return models, scalers

def save_all_models(models, scalers, feature_extractor):
    """Save all models and create enhanced classifier"""
    print("💾 Saving models...")
    
    # Save individual models
    for name, model in models.items():
        joblib.dump(model, f'{name}_model.joblib')
        print(f"Saved {name}_model.joblib")
    
    # Save scalers
    for name, scaler in scalers.items():
        joblib.dump(scaler, f'{name}_scaler.joblib') 
        print(f"Saved {name}_scaler.joblib")
    
    # Save feature extractor
    joblib.dump(feature_extractor, 'feature_extractor.joblib')
    print("Saved feature_extractor.joblib")
    
    # Create and save enhanced classifier
    enhanced_classifier = EnhancedURLClassifier()
    # The enhanced classifier will load models when needed
    joblib.dump(enhanced_classifier, 'enhanced_classifier.joblib')
    print("Saved enhanced_classifier.joblib")

def test_system():
    """Test the complete system"""
    print("\\n🧪 Testing Enhanced System...")
    
    enhanced_classifier = joblib.load('enhanced_classifier.joblib')
    
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com", 
        "https://github.com",
        "https://stackoverflow.com",
        "http://192.168.1.1/malware.exe",
        "http://fake-bank.tk/login.php", 
        "http://bit.ly/suspicious123"
    ]
    
    print("Test Results:")
    print("-" * 50)
    for url in test_urls:
        result = enhanced_classifier.predict_url(url)
        status = "✅" if "benign" in result or "Trusted" in result else "⚠️"
        print(f"{status} {url}")
        print(f"   → {result}")

def main():
    """Main training pipeline"""
    print("🚀 ENHANCED MULTI-DATASET TRAINING")
    print("=" * 50)
    
    try:
        # Download and combine datasets
        combined_df = download_and_combine_datasets()
        
        # Prepare training data  
        X, y, feature_extractor = prepare_training_data(combined_df, sample_size=50000)
        
        # Train models
        models, scalers = train_models_simple(X, y)
        
        # Save everything
        save_all_models(models, scalers, feature_extractor)
        
        # Test system
        test_system()
        
        print("\\n🎉 TRAINING COMPLETE!")
        print("Enhanced classifier ready for use!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()