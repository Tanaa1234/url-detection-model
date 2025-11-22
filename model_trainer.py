"""
Model training and evaluation for URL classification
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.preprocessing import StandardScaler
import joblib
import os
import time
from data_preprocessing import URLFeatureExtractor, load_and_preprocess_data

class URLClassifierTrainer:
    """Train and evaluate multiple ML models for URL classification"""
    
    def __init__(self, feature_extractor=None):
        self.feature_extractor = feature_extractor or URLFeatureExtractor()
        self.models = {}
        self.scalers = {}
        self.best_params = {}
        self.results = {}
        
    def initialize_models(self):
        """Initialize all ML models"""
        self.models = {
            'Random Forest': RandomForestClassifier(random_state=42, n_jobs=-1),
            'XGBoost': XGBClassifier(random_state=42, eval_metric='mlogloss'),
            'KNN': KNeighborsClassifier(),
            'SVM': SVC(random_state=42, probability=True)
        }
        
        # Initialize scalers for models that need scaling
        self.scalers = {
            'KNN': StandardScaler(),
            'SVM': StandardScaler()
        }
        
    def get_hyperparameter_grids(self):
        """Define hyperparameter grids for each model"""
        return {
            'Random Forest': {
                'n_estimators': [100, 200],
                'max_depth': [10, 20, None],
                'min_samples_split': [2, 5],
                'min_samples_leaf': [1, 2]
            },
            'XGBoost': {
                'n_estimators': [100, 200],
                'max_depth': [6, 10],
                'learning_rate': [0.1, 0.01],
                'subsample': [0.8, 1.0]
            },
            'KNN': {
                'n_neighbors': [3, 5, 7, 9],
                'weights': ['uniform', 'distance'],
                'metric': ['euclidean', 'manhattan']
            },
            'SVM': {
                'C': [0.1, 1, 10],
                'kernel': ['rbf', 'linear'],
                'gamma': ['scale', 'auto']
            }
        }
    
    def train_model_with_grid_search(self, model_name, X_train, y_train, param_grid):
        """Train a single model with grid search"""
        print(f"Training {model_name} with grid search...")
        
        start_time = time.time()
        
        # Scale data if needed
        X_train_scaled = X_train.copy()
        if model_name in self.scalers:
            X_train_scaled = self.scalers[model_name].fit_transform(X_train)
        
        # Grid search
        grid_search = GridSearchCV(
            self.models[model_name],
            param_grid,
            cv=3,  # Reduced for speed
            scoring='accuracy',
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_train_scaled, y_train)
        
        # Store best model and parameters
        self.models[model_name] = grid_search.best_estimator_
        self.best_params[model_name] = grid_search.best_params_
        
        training_time = time.time() - start_time
        print(f"{model_name} training completed in {training_time:.2f} seconds")
        print(f"Best parameters: {grid_search.best_params_}")
        
        return grid_search.best_score_
    
    def train_all_models(self, X_train, y_train, use_grid_search=True):
        """Train all models"""
        self.initialize_models()
        
        if use_grid_search:
            param_grids = self.get_hyperparameter_grids()
            
            for model_name in self.models.keys():
                try:
                    best_score = self.train_model_with_grid_search(
                        model_name, X_train, y_train, param_grids[model_name]
                    )
                    print(f"{model_name} best cross-validation score: {best_score:.4f}")
                except Exception as e:
                    print(f"Error training {model_name}: {e}")
        else:
            # Train with default parameters
            for model_name, model in self.models.items():
                print(f"Training {model_name}...")
                start_time = time.time()
                
                X_train_scaled = X_train.copy()
                if model_name in self.scalers:
                    X_train_scaled = self.scalers[model_name].fit_transform(X_train)
                
                model.fit(X_train_scaled, y_train)
                
                training_time = time.time() - start_time
                print(f"{model_name} training completed in {training_time:.2f} seconds")
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate all trained models"""
        print("\nEvaluating models...")
        
        for model_name, model in self.models.items():
            print(f"\n=== {model_name} Results ===")
            
            try:
                # Scale test data if needed
                X_test_scaled = X_test.copy()
                if model_name in self.scalers:
                    X_test_scaled = self.scalers[model_name].transform(X_test)
                
                # Make predictions
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled) if hasattr(model, 'predict_proba') else None
                
                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
                
                self.results[model_name] = {
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1_score': f1,
                    'predictions': y_pred,
                    'probabilities': y_pred_proba
                }
                
                print(f"Accuracy: {accuracy:.4f}")
                print(f"Precision: {precision:.4f}")
                print(f"Recall: {recall:.4f}")
                print(f"F1-Score: {f1:.4f}")
                
                # Detailed classification report
                print("\nClassification Report:")
                class_names = self.feature_extractor.get_class_names()
                print(classification_report(y_test, y_pred, target_names=class_names))
                
            except Exception as e:
                print(f"Error evaluating {model_name}: {e}")
    
    def save_models(self, models_dir='models'):
        """Save trained models and scalers"""
        os.makedirs(models_dir, exist_ok=True)
        
        for model_name, model in self.models.items():
            # Save model
            model_filename = f"{models_dir}/{model_name.lower().replace(' ', '_')}_model.joblib"
            joblib.dump(model, model_filename)
            print(f"Saved {model_name} to {model_filename}")
            
            # Save scaler if exists
            if model_name in self.scalers:
                scaler_filename = f"{models_dir}/{model_name.lower().replace(' ', '_')}_scaler.joblib"
                joblib.dump(self.scalers[model_name], scaler_filename)
                print(f"Saved {model_name} scaler to {scaler_filename}")
        
        # Save feature extractor
        extractor_filename = f"{models_dir}/feature_extractor.joblib"
        joblib.dump(self.feature_extractor, extractor_filename)
        print(f"Saved feature extractor to {extractor_filename}")
        
        # Save results
        results_filename = f"{models_dir}/model_results.joblib"
        joblib.dump(self.results, results_filename)
        print(f"Saved results to {results_filename}")
    
    def load_models(self, models_dir='models'):
        """Load trained models and scalers"""
        model_files = {
            'Random Forest': 'random_forest_model.joblib',
            'XGBoost': 'xgboost_model.joblib',
            'KNN': 'knn_model.joblib',
            'SVM': 'svm_model.joblib'
        }
        
        scaler_files = {
            'KNN': 'knn_scaler.joblib',
            'SVM': 'svm_scaler.joblib'
        }
        
        # Load models
        for model_name, filename in model_files.items():
            filepath = os.path.join(models_dir, filename)
            if os.path.exists(filepath):
                self.models[model_name] = joblib.load(filepath)
                print(f"Loaded {model_name}")
        
        # Load scalers
        for model_name, filename in scaler_files.items():
            filepath = os.path.join(models_dir, filename)
            if os.path.exists(filepath):
                self.scalers[model_name] = joblib.load(filepath)
                print(f"Loaded {model_name} scaler")
        
        # Load feature extractor
        extractor_path = os.path.join(models_dir, 'feature_extractor.joblib')
        if os.path.exists(extractor_path):
            self.feature_extractor = joblib.load(extractor_path)
            print("Loaded feature extractor")
    
    def predict_url(self, url):
        """Predict the class of a single URL using all models"""
        # Extract features
        url_features = self.feature_extractor.transform_single_url(url)
        
        predictions = {}
        for model_name, model in self.models.items():
            try:
                # Scale features if needed
                features_scaled = url_features.copy()
                if model_name in self.scalers:
                    features_scaled = self.scalers[model_name].transform(features_scaled)
                
                # Make prediction
                pred = model.predict(features_scaled)[0]
                pred_proba = model.predict_proba(features_scaled)[0] if hasattr(model, 'predict_proba') else None
                
                # Convert to class name
                class_name = self.feature_extractor.label_encoder.inverse_transform([pred])[0]
                
                predictions[model_name] = {
                    'prediction': class_name,
                    'probabilities': pred_proba,
                    'confidence': max(pred_proba) if pred_proba is not None else None
                }
                
            except Exception as e:
                print(f"Error predicting with {model_name}: {e}")
                predictions[model_name] = {
                    'prediction': 'Error',
                    'probabilities': None,
                    'confidence': None
                }
        
        return predictions
    
    def get_model_summary(self):
        """Get summary of model performance"""
        if not self.results:
            return "No evaluation results available"
        
        summary = []
        for model_name, results in self.results.items():
            summary.append({
                'Model': model_name,
                'Accuracy': f"{results['accuracy']:.4f}",
                'Precision': f"{results['precision']:.4f}",
                'Recall': f"{results['recall']:.4f}",
                'F1-Score': f"{results['f1_score']:.4f}"
            })
        
        return pd.DataFrame(summary)

def main():
    """Main training function"""
    print("Loading and preprocessing data...")
    
    # Load data (use a sample for faster training during development)
    df = load_and_preprocess_data()
    
    # Use a sample for faster training (remove this for full training)
    sample_size = 50000  # Adjust based on your system's capacity
    if len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42)
        print(f"Using sample of {sample_size} rows for training")
    
    # Prepare data
    feature_extractor = URLFeatureExtractor()
    X_train, X_test, y_train, y_test, feature_names = feature_extractor.prepare_data(df)
    
    # Train models
    trainer = URLClassifierTrainer(feature_extractor)
    
    # Train with grid search (set to False for faster training with default params)
    use_grid_search = False  # Set to True for better performance but slower training
    trainer.train_all_models(X_train, y_train, use_grid_search=use_grid_search)
    
    # Evaluate models
    trainer.evaluate_models(X_test, y_test)
    
    # Save models
    trainer.save_models()
    
    # Print summary
    print("\n=== Model Performance Summary ===")
    print(trainer.get_model_summary())
    
    print("\nTraining complete! Models saved to 'models/' directory.")

if __name__ == "__main__":
    main()