"""
Improved model training with better techniques and full dataset
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
import joblib
import os
import time
from data_preprocessing import URLFeatureExtractor
import kagglehub

class ImprovedURLClassifier:
    """Improved URL classifier with better training techniques"""
    
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.models = {}
        self.scalers = {}
        self.results = {}
        
    def load_full_dataset(self):
        """Load the full dataset from Kaggle"""
        print("Downloading full dataset from Kaggle...")
        path = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
        
        csv_path = f"{path}/malicious_phish.csv"
        df = pd.read_csv(csv_path)
        
        print(f"Loaded {len(df)} URLs")
        print("Target distribution:")
        print(df['type'].value_counts())
        
        return df
    
    def preprocess_and_balance_data(self, df, sample_size=None):
        """Preprocess data with better balancing"""
        print("Preprocessing and balancing data...")
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['url'])
        print(f"After removing duplicates: {len(df)} URLs")
        
        # Balance the dataset by sampling from each class
        if sample_size:
            # Sample equally from each class
            class_counts = df['type'].value_counts()
            samples_per_class = min(sample_size // 4, class_counts.min())
            
            balanced_dfs = []
            for class_name in df['type'].unique():
                class_df = df[df['type'] == class_name].sample(n=samples_per_class, random_state=42)
                balanced_dfs.append(class_df)
            
            df = pd.concat(balanced_dfs, ignore_index=True)
            df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
            
            print(f"Balanced dataset: {len(df)} URLs")
            print("Balanced distribution:")
            print(df['type'].value_counts())
        
        # Extract features
        X_train, X_test, y_train, y_test, feature_names = self.feature_extractor.prepare_data(df)
        
        return X_train, X_test, y_train, y_test, feature_names
    
    def get_improved_models(self):
        """Get models with class balancing"""
        # Calculate class weights for imbalanced data
        classes = np.unique(self.y_train)
        class_weights = compute_class_weight('balanced', classes=classes, y=self.y_train)
        class_weight_dict = dict(zip(classes, class_weights))
        
        models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            ),
            'XGBoost': XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss'
            ),
            'KNN': KNeighborsClassifier(
                n_neighbors=7,
                weights='distance',
                metric='euclidean'
            ),
            'SVM': SVC(
                C=1.0,
                kernel='rbf',
                gamma='scale',
                class_weight='balanced',
                probability=True,
                random_state=42
            )
        }
        
        return models
    
    def train_with_validation(self, X_train, y_train):
        """Train models with proper cross-validation"""
        print("Training models with cross-validation...")
        
        self.X_train = X_train
        self.y_train = y_train
        
        models = self.get_improved_models()
        
        # Initialize scalers for models that need scaling
        scalers = {
            'KNN': StandardScaler(),
            'SVM': StandardScaler()
        }
        
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        
        for model_name, model in models.items():
            print(f"\nTraining {model_name}...")
            start_time = time.time()
            
            # Prepare data (scale if needed)
            X_train_processed = X_train.copy()
            if model_name in scalers:
                X_train_processed = scalers[model_name].fit_transform(X_train)
                self.scalers[model_name] = scalers[model_name]
            
            # Cross-validation
            cv_scores = cross_val_score(model, X_train_processed, y_train, cv=cv, scoring='accuracy')
            print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            
            # Train final model
            model.fit(X_train_processed, y_train)
            self.models[model_name] = model
            
            training_time = time.time() - start_time
            print(f"Training completed in {training_time:.2f} seconds")
    
    def evaluate_on_test_set(self, X_test, y_test):
        """Evaluate models on test set"""
        print("\nEvaluating on test set...")
        
        # Test on known good URLs first
        test_good_urls = [
            'https://www.google.com',
            'https://www.facebook.com',
            'https://www.amazon.com',
            'https://www.microsoft.com',
            'https://www.apple.com',
            'https://www.github.com',
            'https://www.wikipedia.org',
            'https://www.stackoverflow.com'
        ]
        
        print("\nTesting on known legitimate URLs:")
        for url in test_good_urls:
            predictions = self.predict_url(url)
            benign_votes = sum(1 for pred in predictions.values() if pred['prediction'] == 'benign')
            print(f"{url}: {benign_votes}/4 models predict 'benign'")
        
        # Regular evaluation
        for model_name, model in self.models.items():
            print(f"\n=== {model_name} Results ===")
            
            # Scale test data if needed
            X_test_processed = X_test.copy()
            if model_name in self.scalers:
                X_test_processed = self.scalers[model_name].transform(X_test)
            
            # Make predictions
            y_pred = model.predict(X_test_processed)
            y_pred_proba = model.predict_proba(X_test_processed)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
            
            self.results[model_name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1
            }
            
            print(f"Accuracy: {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall: {recall:.4f}")
            print(f"F1-Score: {f1:.4f}")
            
            # Detailed classification report
            class_names = self.feature_extractor.get_class_names()
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred, target_names=class_names))
    
    def predict_url(self, url):
        """Predict URL with all models"""
        url_features = self.feature_extractor.transform_single_url(url)
        
        predictions = {}
        for model_name, model in self.models.items():
            try:
                # Scale features if needed
                features_processed = url_features.copy()
                if model_name in self.scalers:
                    features_processed = self.scalers[model_name].transform(features_processed)
                
                # Make prediction
                pred = model.predict(features_processed)[0]
                pred_proba = model.predict_proba(features_processed)[0]
                
                # Convert to class name
                class_name = self.feature_extractor.label_encoder.inverse_transform([pred])[0]
                
                predictions[model_name] = {
                    'prediction': class_name,
                    'probabilities': pred_proba,
                    'confidence': max(pred_proba)
                }
                
            except Exception as e:
                print(f"Error predicting with {model_name}: {e}")
                predictions[model_name] = {
                    'prediction': 'Error',
                    'probabilities': None,
                    'confidence': None
                }
        
        return predictions
    
    def save_models(self, models_dir='models'):
        """Save trained models"""
        os.makedirs(models_dir, exist_ok=True)
        
        for model_name, model in self.models.items():
            model_filename = f"{models_dir}/{model_name.lower().replace(' ', '_')}_model.joblib"
            joblib.dump(model, model_filename)
            print(f"Saved {model_name} to {model_filename}")
            
            if model_name in self.scalers:
                scaler_filename = f"{models_dir}/{model_name.lower().replace(' ', '_')}_scaler.joblib"
                joblib.dump(self.scalers[model_name], scaler_filename)
        
        # Save feature extractor
        joblib.dump(self.feature_extractor, f"{models_dir}/feature_extractor.joblib")
        joblib.dump(self.results, f"{models_dir}/model_results.joblib")
        print("All models saved successfully!")

def main():
    """Main improved training function"""
    print("🔄 IMPROVED URL DETECTION MODEL TRAINING")
    print("="*60)
    
    classifier = ImprovedURLClassifier()
    
    # Load full dataset
    df = classifier.load_full_dataset()
    
    # Use larger sample for better training (adjust based on your system)
    sample_size = 100000  # Increase this for better accuracy (max: 651191)
    print(f"Using sample size: {sample_size}")
    
    # Preprocess and balance data
    X_train, X_test, y_train, y_test, feature_names = classifier.preprocess_and_balance_data(df, sample_size)
    
    # Train models with validation
    classifier.train_with_validation(X_train, y_train)
    
    # Evaluate models
    classifier.evaluate_on_test_set(X_test, y_test)
    
    # Save improved models
    classifier.save_models()
    
    print("\n✅ Improved training complete!")
    print("Models should now perform much better on legitimate URLs.")

if __name__ == "__main__":
    main()