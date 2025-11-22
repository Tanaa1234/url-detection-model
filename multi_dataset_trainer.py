#!/usr/bin/env python3
"""
Enhanced URL Maliciousness Detection - Multi-Dataset Trainer
Combines multiple Kaggle datasets for better model performance
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

class MultiDatasetTrainer:
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.models = {}
        self.scalers = {}
        
    def download_datasets(self):
        """Download both Kaggle datasets"""
        print("📦 Downloading datasets...")
        
        # Dataset 1: Original malicious URLs dataset
        print("Downloading dataset 1: sid321axn/malicious-urls-dataset")
        path1 = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
        print(f"Dataset 1 path: {path1}")
        
        # Dataset 2: Balanced benign and malicious URLs
        print("Downloading dataset 2: samahsadiq/benign-and-malicious-urls")
        path2 = kagglehub.dataset_download("samahsadiq/benign-and-malicious-urls")
        print(f"Dataset 2 path: {path2}")
        
        return path1, path2
    
    def load_and_combine_datasets(self, path1, path2):
        """Load and combine both datasets"""
        print("🔄 Loading and combining datasets...")
        
        # Load dataset 1 (original)
        df1 = pd.read_csv(os.path.join(path1, 'malicious_phish.csv'))
        print(f"Dataset 1 shape: {df1.shape}")
        print("Dataset 1 labels:", df1['type'].value_counts().to_dict())
        
        # Convert to binary classification for dataset 1
        df1_processed = df1.copy()
        df1_processed['label'] = df1_processed['type'].apply(
            lambda x: 'benign' if x == 'benign' else 'malicious'
        )
        df1_processed = df1_processed[['url', 'label']].copy()
        
        # Load dataset 2 (balanced)
        df2 = pd.read_csv(os.path.join(path2, 'balanced_urls.csv'))
        print(f"Dataset 2 shape: {df2.shape}")
        print("Dataset 2 labels:", df2['label'].value_counts().to_dict())
        
        # Keep only url and label columns for dataset 2
        df2_processed = df2[['url', 'label']].copy()
        
        # Combine datasets
        combined_df = pd.concat([df1_processed, df2_processed], ignore_index=True)
        print(f"\nCombined dataset shape: {combined_df.shape}")
        print("Combined labels:", combined_df['label'].value_counts().to_dict())
        
        # Remove duplicates
        initial_size = len(combined_df)
        combined_df = combined_df.drop_duplicates(subset=['url'], keep='first')
        print(f"Removed {initial_size - len(combined_df)} duplicate URLs")
        print(f"Final dataset shape: {combined_df.shape}")
        
        return combined_df
    
    def clean_and_validate_data(self, df):
        """Clean and validate the combined dataset"""
        print("🧹 Cleaning and validating data...")
        
        # Remove null values
        initial_size = len(df)
        df = df.dropna().copy()
        print(f"Removed {initial_size - len(df)} rows with null values")
        
        # Validate URLs (basic check)
        valid_urls = df['url'].str.contains(r'^https?://', na=False)
        df = df[valid_urls].copy()
        print(f"Kept {len(df)} valid URLs (with http/https)")
        
        # Remove extremely long URLs (likely corrupted)
        df = df[df['url'].str.len() < 2000].copy()
        print(f"Kept {len(df)} URLs under 2000 characters")
        
        # Ensure binary labels
        df = df[df['label'].isin(['benign', 'malicious'])].copy()
        print(f"Final cleaned dataset: {len(df)} URLs")
        print("Final label distribution:", df['label'].value_counts().to_dict())
        
        return df
    
    def extract_features_batch(self, urls, batch_size=1000):
        """Extract features in batches to handle large datasets"""
        print(f"🔍 Extracting features for {len(urls)} URLs...")
        
        features_list = []
        total_batches = (len(urls) - 1) // batch_size + 1
        
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            print(f"Processing batch {i//batch_size + 1}/{total_batches}")
            
            batch_features = []
            for url in batch:
                try:
                    features_dict = self.feature_extractor.extract_url_features(url)
                    # Convert dictionary to list of values using the actual keys in order
                    features_list = [
                        features_dict['url_length'], features_dict['domain_length'], features_dict['path_length'], 
                        features_dict['query_length'], features_dict['fragment_length'], features_dict['is_trusted_domain'],
                        features_dict['subdomain_length'], features_dict['tld_length'], features_dict['domain_tokens'],
                        features_dict['digit_count'], features_dict['letter_count'], features_dict['special_char_count'],
                        features_dict['uppercase_count'], features_dict['lowercase_count'], features_dict['dot_count'],
                        features_dict['dash_count'], features_dict['underscore_count'], features_dict['slash_count'],
                        features_dict['question_mark_count'], features_dict['equals_count'], features_dict['at_count'],
                        features_dict['ampersand_count'], features_dict['percent_count'], features_dict['hash_count'],
                        features_dict['semicolon_count'], features_dict['has_ip'], features_dict['has_shortening'],
                        features_dict['has_suspicious_tld'], features_dict['has_common_tld'], features_dict['domain_has_www'],
                        features_dict['domain_is_simple'], features_dict['is_https'], features_dict['has_port'],
                        features_dict['url_depth'], float(features_dict['url_entropy']), float(features_dict['domain_entropy']),
                        float(features_dict['digit_ratio']), float(features_dict['letter_ratio']), float(features_dict['special_char_ratio'])
                    ]
                    batch_features.append(features_list)
                except Exception as e:
                    # Use default features for problematic URLs
                    print(f"Error processing {url}: {e}")
                    batch_features.append([0.0] * 39)  # 39 features
            
            features_list.extend(batch_features)
        
        return np.array(features_list)
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train all machine learning models"""
        print("🤖 Training machine learning models...")
        
        # Convert labels to binary
        y_train_binary = (y_train == 'malicious').astype(int)
        y_test_binary = (y_test == 'malicious').astype(int)
        
        models_config = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
            'xgboost': xgb.XGBClassifier(
                n_estimators=100,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                n_jobs=-1
            ),
            'knn': KNeighborsClassifier(
                n_neighbors=5,
                weights='distance',
                n_jobs=-1
            ),
            'svm': SVC(
                C=1.0,
                kernel='rbf',
                probability=True,
                random_state=42
            )
        }
        
        results = {}
        
        for name, model in models_config.items():
            print(f"\nTraining {name.upper()}...")
            
            # Scale features for KNN and SVM
            if name in ['knn', 'svm']:
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)
                self.scalers[name] = scaler
                
                model.fit(X_train_scaled, y_train_binary)
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            else:
                model.fit(X_train, y_train_binary)
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Calculate metrics
            accuracy = accuracy_score(y_test_binary, y_pred)
            
            self.models[name] = model
            results[name] = {
                'accuracy': accuracy,
                'predictions': y_pred,
                'probabilities': y_pred_proba
            }
            
            print(f"{name.upper()} Accuracy: {accuracy:.4f}")
        
        return results
    
    def save_models(self):
        """Save all trained models and components"""
        print("💾 Saving models...")
        
        # Save individual models
        for name, model in self.models.items():
            joblib.dump(model, f'{name}_model.joblib')
            print(f"Saved {name}_model.joblib")
        
        # Save scalers
        for name, scaler in self.scalers.items():
            joblib.dump(scaler, f'{name}_scaler.joblib')
            print(f"Saved {name}_scaler.joblib")
        
        # Save feature extractor
        joblib.dump(self.feature_extractor, 'feature_extractor.joblib')
        print("Saved feature_extractor.joblib")
        
        # Create and save enhanced classifier
        enhanced_classifier = EnhancedURLClassifier(
            models=self.models,
            scalers=self.scalers,
            feature_extractor=self.feature_extractor
        )
        joblib.dump(enhanced_classifier, 'enhanced_classifier.joblib')
        print("Saved enhanced_classifier.joblib")
    
    def test_enhanced_classifier(self):
        """Test the enhanced classifier with sample URLs"""
        print("\n🧪 Testing Enhanced Classifier...")
        
        # Load the enhanced classifier
        enhanced_classifier = joblib.load('enhanced_classifier.joblib')
        
        test_urls = [
            "https://www.google.com",
            "https://github.com", 
            "https://www.facebook.com",
            "https://stackoverflow.com",
            "http://192.168.1.1/malware.exe",
            "http://fake-bank.tk/login.php",
            "http://bit.ly/suspicious123",
            "https://phishing-site.ml/secure/"
        ]
        
        print("\nTest Results:")
        print("-" * 50)
        for url in test_urls:
            result = enhanced_classifier.predict_url(url)
            status = "✅" if "benign" in result or "Trusted" in result else "⚠️"
            print(f"{status} {url}")
            print(f"   → {result}")
    
    def run_full_training(self):
        """Run the complete training pipeline"""
        print("🚀 Starting Multi-Dataset Training Pipeline")
        print("=" * 60)
        
        # Download datasets
        path1, path2 = self.download_datasets()
        
        # Load and combine datasets
        combined_df = self.load_and_combine_datasets(path1, path2)
        
        # Clean and validate data
        clean_df = self.clean_and_validate_data(combined_df)
        
        # Sample data for faster training (optional - remove for full dataset)
        if len(clean_df) > 100000:
            print(f"Sampling 100,000 URLs for faster training (from {len(clean_df)} total)")
            clean_df = clean_df.sample(n=100000, random_state=42).copy()
        
        # Split data
        print("Splitting data into train/test sets...")
        X_urls = clean_df['url'].values
        y_labels = clean_df['label'].values
        
        X_train_urls, X_test_urls, y_train, y_test = train_test_split(
            X_urls, y_labels, test_size=0.2, random_state=42, stratify=y_labels
        )
        
        print(f"Training set: {len(X_train_urls)} URLs")
        print(f"Test set: {len(X_test_urls)} URLs")
        
        # Extract features
        X_train = self.extract_features_batch(X_train_urls)
        X_test = self.extract_features_batch(X_test_urls)
        
        # Train models
        results = self.train_models(X_train, X_test, y_train, y_test)
        
        # Print results summary
        print("\n📊 TRAINING RESULTS SUMMARY")
        print("=" * 40)
        for name, metrics in results.items():
            print(f"{name.upper()}: {metrics['accuracy']:.4f} accuracy")
        
        # Save everything
        self.save_models()
        
        # Test enhanced classifier
        self.test_enhanced_classifier()
        
        print("\n🎉 Training Complete!")
        print("Models saved and ready for use in Streamlit app!")

if __name__ == "__main__":
    trainer = MultiDatasetTrainer()
    trainer.run_full_training()