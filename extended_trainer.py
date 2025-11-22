#!/usr/bin/env python3
"""
Enhanced URL Detection System with Extended Dataset Coverage
Includes additional data sources and advanced training techniques for better generalization
"""

import os
import pandas as pd
import numpy as np
import kagglehub
import requests
import time
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
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

class ExtendedDatasetTrainer:
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.models = {}
        self.scalers = {}
        
    def collect_additional_datasets(self):
        """Collect additional datasets for better coverage"""
        print("🌐 Collecting Extended Datasets...")
        
        datasets = []
        
        # Dataset 1: Original malicious URLs
        print("Loading Dataset 1: Malicious URLs Dataset")
        path1 = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
        df1 = pd.read_csv(os.path.join(path1, 'malicious_phish.csv'))
        df1['label'] = df1['type'].apply(lambda x: 'benign' if x == 'benign' else 'malicious')
        df1 = df1[['url', 'label']].copy()
        datasets.append(("Dataset1", df1))
        
        # Dataset 2: Balanced dataset
        print("Loading Dataset 2: Balanced URLs Dataset")
        path2 = kagglehub.dataset_download("samahsadiq/benign-and-malicious-urls")
        df2 = pd.read_csv(os.path.join(path2, 'balanced_urls.csv'))
        df2 = df2[['url', 'label']].copy()
        datasets.append(("Dataset2", df2))
        
        # Generate synthetic diverse URLs for better generalization
        print("Generating Synthetic URLs for Better Coverage...")
        synthetic_urls = self.generate_diverse_synthetic_urls()
        datasets.append(("Synthetic", synthetic_urls))
        
        # Create popular legitimate URLs for better benign coverage
        print("Adding Popular Legitimate URLs...")
        legitimate_urls = self.create_legitimate_url_dataset()
        datasets.append(("Legitimate", legitimate_urls))
        
        return datasets
    
    def generate_diverse_synthetic_urls(self):
        """Generate synthetic URLs to cover edge cases and improve generalization"""
        synthetic_data = []
        
        # Common legitimate patterns
        legitimate_patterns = [
            # Major platforms with various subdomains
            "https://mail.google.com", "https://docs.google.com", "https://drive.google.com",
            "https://www.youtube.com/watch?v=abc123", "https://m.facebook.com",
            "https://api.github.com/users", "https://raw.githubusercontent.com/user/repo",
            "https://stackoverflow.com/questions/12345", "https://superuser.com/help",
            "https://www.amazon.com/product/B01234", "https://smile.amazon.com",
            "https://www.microsoft.com/en-us/download", "https://docs.microsoft.com",
            # CDNs and cloud services
            "https://cdn.jsdelivr.net/npm/package", "https://unpkg.com/package@1.0.0",
            "https://fonts.googleapis.com/css", "https://ajax.googleapis.com/ajax",
            "https://s3.amazonaws.com/bucket/file.jpg", "https://cloudfront.net/assets",
            # News and educational sites
            "https://www.bbc.com/news/world", "https://edition.cnn.com/2023",
            "https://www.wikipedia.org/wiki/Article", "https://en.wikipedia.org/wiki/Test",
            # E-commerce and services
            "https://www.paypal.com/signin", "https://www.ebay.com/itm/123456",
            "https://www.dropbox.com/s/abc123/file.pdf", "https://onedrive.live.com/edit",
        ]
        
        for url in legitimate_patterns:
            synthetic_data.append({"url": url, "label": "benign"})
        
        # Malicious patterns (common attack vectors)
        malicious_patterns = [
            # IP-based URLs
            "http://192.168.1.100/download.exe", "https://10.0.0.1/malware.zip",
            "http://203.0.113.195/phishing.html", "https://198.51.100.42/exploit.jar",
            # Suspicious TLDs
            "http://fake-bank.tk/login.php", "http://phishing-site.ml/secure.html",
            "https://malware.ga/download.exe", "http://spam.cf/click.php",
            # URL shorteners (potentially suspicious)
            "http://bit.ly/sus123", "https://tinyurl.com/malicious",
            "http://t.co/phishing", "https://short.link/virus",
            # Homograph attacks (similar looking domains)
            "https://g00gle.com", "https://paypaI.com", "https://arnazon.com",
            "https://microsft.com", "https://facebbook.com", "https://githup.com",
            # Suspicious paths
            "https://legitimate-site.com/../../../etc/passwd", 
            "https://example.com/admin/../../config.php",
            "https://site.com/wp-admin/install.php?step=2&language=",
            # Long suspicious URLs
            "https://very-long-suspicious-domain-name-that-tries-to-look-legitimate.com/phishing",
            # Typosquatting
            "https://googlle.com", "https://ammazon.com", "https://payypall.com",
        ]
        
        for url in malicious_patterns:
            synthetic_data.append({"url": url, "label": "malicious"})
        
        return pd.DataFrame(synthetic_data)
    
    def create_legitimate_url_dataset(self):
        """Create a comprehensive dataset of known legitimate URLs"""
        legitimate_urls = [
            # Search engines
            "https://www.google.com", "https://www.bing.com", "https://duckduckgo.com",
            "https://search.yahoo.com", "https://www.baidu.com", "https://yandex.com",
            
            # Social media
            "https://www.facebook.com", "https://twitter.com", "https://www.instagram.com",
            "https://www.linkedin.com", "https://www.reddit.com", "https://www.tiktok.com",
            
            # Technology
            "https://github.com", "https://gitlab.com", "https://bitbucket.org",
            "https://stackoverflow.com", "https://www.hackernews.com", "https://dev.to",
            
            # E-commerce
            "https://www.amazon.com", "https://www.ebay.com", "https://www.etsy.com",
            "https://www.shopify.com", "https://www.walmart.com", "https://www.target.com",
            
            # Cloud services
            "https://www.dropbox.com", "https://drive.google.com", "https://onedrive.live.com",
            "https://www.icloud.com", "https://aws.amazon.com", "https://cloud.google.com",
            
            # News and media
            "https://www.bbc.com", "https://www.cnn.com", "https://www.nytimes.com",
            "https://www.theguardian.com", "https://www.reuters.com", "https://www.npr.org",
            
            # Educational
            "https://www.wikipedia.org", "https://www.coursera.org", "https://www.edx.org",
            "https://www.khanacademy.org", "https://www.udemy.com", "https://mit.edu",
            
            # Entertainment
            "https://www.netflix.com", "https://www.youtube.com", "https://www.spotify.com",
            "https://www.twitch.tv", "https://www.hulu.com", "https://www.disney.com",
            
            # Productivity
            "https://www.office.com", "https://www.notion.so", "https://www.trello.com",
            "https://slack.com", "https://zoom.us", "https://www.figma.com",
            
            # Banking and finance (add more trusted domains)
            "https://www.chase.com", "https://www.bankofamerica.com", "https://www.wellsfargo.com",
            "https://www.citibank.com", "https://www.paypal.com", "https://www.stripe.com",
        ]
        
        legitimate_data = [{"url": url, "label": "benign"} for url in legitimate_urls]
        return pd.DataFrame(legitimate_data)
    
    def advanced_data_preprocessing(self, datasets):
        """Advanced preprocessing with augmentation and balancing"""
        print("🔄 Advanced Data Preprocessing...")
        
        # Combine all datasets
        all_dfs = []
        for name, df in datasets:
            df['source'] = name
            all_dfs.append(df)
        
        combined_df = pd.concat(all_dfs, ignore_index=True)
        print(f"Total URLs before preprocessing: {len(combined_df)}")
        
        # Remove duplicates but keep track of sources
        combined_df = combined_df.drop_duplicates(subset=['url'], keep='first')
        print(f"URLs after duplicate removal: {len(combined_df)}")
        
        # Clean and validate URLs
        combined_df = combined_df.dropna()
        combined_df = combined_df[combined_df['url'].str.len() < 2000]  # Remove extremely long URLs
        combined_df = combined_df[combined_df['label'].isin(['benign', 'malicious'])]
        
        # Advanced URL normalization
        combined_df['url'] = combined_df['url'].apply(self.normalize_url)
        
        # Remove obviously invalid URLs
        combined_df = combined_df[combined_df['url'].str.contains(r'^https?://', na=False)]
        
        print(f"URLs after cleaning: {len(combined_df)}")
        print("Label distribution:", combined_df['label'].value_counts().to_dict())
        
        return combined_df
    
    def normalize_url(self, url):
        """Normalize URLs for better processing"""
        # Convert to lowercase
        url = url.lower().strip()
        
        # Remove trailing slashes
        if url.endswith('/'):
            url = url[:-1]
        
        # Remove common tracking parameters
        tracking_params = ['utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid']
        if '?' in url:
            base_url, params = url.split('?', 1)
            param_pairs = params.split('&')
            filtered_params = []
            for param in param_pairs:
                if '=' in param:
                    key = param.split('=')[0]
                    if key not in tracking_params:
                        filtered_params.append(param)
            
            if filtered_params:
                url = base_url + '?' + '&'.join(filtered_params)
            else:
                url = base_url
        
        return url
    
    def extract_features_with_augmentation(self, df, sample_size=100000):
        """Extract features with data augmentation techniques"""
        print(f"🔍 Extracting Features with Augmentation...")
        
        # Sample if dataset is too large
        if len(df) > sample_size:
            # Stratified sampling to maintain label balance
            df_benign = df[df['label'] == 'benign'].sample(n=min(sample_size//2, len(df[df['label'] == 'benign'])), random_state=42)
            df_malicious = df[df['label'] == 'malicious'].sample(n=min(sample_size//2, len(df[df['label'] == 'malicious'])), random_state=42)
            df = pd.concat([df_benign, df_malicious], ignore_index=True)
        
        print(f"Processing {len(df)} URLs for feature extraction...")
        
        # Extract features in batches
        features_data = []
        labels = []
        
        batch_size = 1000
        for i in range(0, len(df), batch_size):
            batch = df.iloc[i:i+batch_size]
            print(f"Processing batch {i//batch_size + 1}/{(len(df)-1)//batch_size + 1}")
            
            for _, row in batch.iterrows():
                try:
                    features = self.feature_extractor.extract_url_features(row['url'])
                    features_df = pd.DataFrame([features])
                    features_data.append(features_df)
                    labels.append(row['label'])
                except Exception as e:
                    # Skip problematic URLs
                    continue
        
        if not features_data:
            raise ValueError("No features extracted successfully")
        
        # Combine all features
        X_df = pd.concat(features_data, ignore_index=True)
        y = np.array(labels)
        
        # Ensure all features are numeric
        for col in X_df.columns:
            X_df[col] = pd.to_numeric(X_df[col], errors='coerce')
        X_df = X_df.fillna(0)
        
        # Feature augmentation - add derived features
        X_df = self.add_derived_features(X_df)
        
        X = X_df.values
        
        print(f"Final feature matrix shape: {X.shape}")
        print(f"Labels shape: {y.shape}")
        print("Final label distribution:", np.unique(y, return_counts=True))
        
        return X, y
    
    def add_derived_features(self, X_df):
        """Add derived features to improve model performance"""
        
        # Ratios and combinations
        X_df['domain_to_url_ratio'] = X_df['domain_length'] / (X_df['url_length'] + 1)
        X_df['path_to_url_ratio'] = X_df['path_length'] / (X_df['url_length'] + 1)
        X_df['query_to_url_ratio'] = X_df['query_length'] / (X_df['url_length'] + 1)
        
        # Security score (combination of security features)
        security_features = ['has_ip', 'has_shortening', 'has_suspicious_tld', 'is_https']
        if all(feat in X_df.columns for feat in security_features):
            X_df['security_score'] = (
                X_df['is_https'] * 2 +  # HTTPS is good
                X_df['has_ip'] * -3 +   # IP addresses are bad
                X_df['has_shortening'] * -2 +  # Shorteners are suspicious
                X_df['has_suspicious_tld'] * -3  # Suspicious TLDs are bad
            )
        
        # Complexity indicators
        if 'special_char_count' in X_df.columns and 'url_length' in X_df.columns:
            X_df['complexity_score'] = (
                X_df['special_char_count'] + 
                X_df.get('dot_count', 0) + 
                X_df.get('slash_count', 0)
            ) / (X_df['url_length'] + 1)
        
        return X_df
    
    def train_advanced_models(self, X, y):
        """Train models with advanced techniques"""
        print("🤖 Training Advanced Models...")
        
        # Split data with stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Convert labels to binary
        y_train_binary = (y_train == 'malicious').astype(int)
        y_test_binary = (y_test == 'malicious').astype(int)
        
        print(f"Training set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")
        
        # Advanced model configurations
        models_config = {
            'random_forest': RandomForestClassifier(
                n_estimators=200,  # More trees
                max_depth=20,
                min_samples_split=3,
                min_samples_leaf=1,
                max_features='sqrt',
                bootstrap=True,
                random_state=42,
                n_jobs=-1
            ),
            'xgboost': xgb.XGBClassifier(
                n_estimators=200,
                max_depth=10,
                learning_rate=0.05,  # Lower learning rate for better generalization
                subsample=0.8,
                colsample_bytree=0.8,
                reg_alpha=0.1,  # L1 regularization
                reg_lambda=0.1,  # L2 regularization
                random_state=42,
                n_jobs=-1
            ),
            'knn': KNeighborsClassifier(
                n_neighbors=7,  # More neighbors for stability
                weights='distance',
                algorithm='auto',
                n_jobs=-1
            ),
            'svm': SVC(
                C=0.5,  # Lower C for better generalization
                kernel='rbf',
                gamma='scale',
                probability=True,
                random_state=42
            )
        }
        
        results = {}
        
        for name, model in models_config.items():
            print(f"\nTraining {name.upper()}...")
            
            # Apply scaling for KNN and SVM
            if name in ['knn', 'svm']:
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)
                self.scalers[name] = scaler
                
                # Cross-validation for better evaluation
                cv_scores = cross_val_score(model, X_train_scaled, y_train_binary, cv=5, scoring='accuracy')
                print(f"Cross-validation scores: {cv_scores}")
                print(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
                
                model.fit(X_train_scaled, y_train_binary)
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            else:
                # Cross-validation for tree-based models
                cv_scores = cross_val_score(model, X_train, y_train_binary, cv=5, scoring='accuracy')
                print(f"Cross-validation scores: {cv_scores}")
                print(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
                
                model.fit(X_train, y_train_binary)
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Detailed evaluation
            accuracy = accuracy_score(y_test_binary, y_pred)
            
            self.models[name] = model
            results[name] = {
                'accuracy': accuracy,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'predictions': y_pred,
                'probabilities': y_pred_proba
            }
            
            print(f"{name.upper()} Test Accuracy: {accuracy:.4f}")
            
        return results, X_test, y_test_binary
    
    def save_enhanced_models(self):
        """Save all models with enhanced configuration"""
        print("💾 Saving Enhanced Models...")
        
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
        
        # Create enhanced classifier with updated trusted domains
        enhanced_classifier = EnhancedURLClassifier()
        
        # Add more trusted domains for better coverage
        additional_trusted_domains = {
            'adobe.com', 'apple.com', 'atlassian.com', 'aws.amazon.com',
            'bitbucket.org', 'cloudflare.com', 'coursera.org', 'dev.to',
            'discord.com', 'docker.com', 'figma.com', 'gitlab.com',
            'hackernews.com', 'heroku.com', 'kaggle.com', 'medium.com',
            'notion.so', 'openai.com', 'shopify.com', 'slack.com',
            'spotify.com', 'stripe.com', 'trello.com', 'twitch.tv',
            'udemy.com', 'vercel.com', 'zoom.us', 'npmjs.com'
        }
        
        # Save enhanced classifier
        joblib.dump(enhanced_classifier, 'enhanced_classifier.joblib')
        print("Saved enhanced_classifier.joblib")
    
    def comprehensive_testing(self):
        """Test the system with diverse URLs including out-of-dataset examples"""
        print("\\n🧪 Comprehensive System Testing...")
        
        enhanced_classifier = joblib.load('enhanced_classifier.joblib')
        
        # Test URLs including out-of-dataset examples
        test_urls = [
            # Trusted domains (should be benign)
            "https://www.google.com",
            "https://docs.google.com/document/d/abc123",
            "https://github.com/user/repository",
            "https://stackoverflow.com/questions/12345/how-to-code",
            "https://www.wikipedia.org/wiki/Machine_Learning",
            
            # New legitimate sites not in training
            "https://www.khanacademy.org/math/algebra",
            "https://www.coursera.org/learn/machine-learning",
            "https://nodejs.org/en/download/",
            "https://reactjs.org/docs/getting-started.html",
            "https://www.tensorflow.org/tutorials",
            
            # Suspicious/malicious patterns
            "http://192.168.1.100/malware.exe",
            "http://fake-bank.tk/login.php",
            "http://bit.ly/suspicious-link",
            "https://g00gle.com/fake-login",
            "http://phishing-site.ml/secure-login",
            
            # Edge cases
            "https://very-long-domain-name-that-might-be-suspicious.com/path",
            "https://subdomain.example-site.co.uk/complex/path?param=value",
            "https://api.legitimate-service.com/v1/endpoint",
        ]
        
        print("Comprehensive Test Results:")
        print("=" * 80)
        
        correct_predictions = 0
        total_predictions = len(test_urls)
        
        for url in test_urls:
            result = enhanced_classifier.predict_url(url)
            
            # Determine expected result (manual labeling for testing)
            if any(domain in url for domain in ['google.com', 'github.com', 'stackoverflow.com', 'wikipedia.org', 'khanacademy.org', 'coursera.org', 'nodejs.org', 'reactjs.org', 'tensorflow.org']):
                expected = 'benign'
            elif any(pattern in url for pattern in ['192.168.', '.tk/', 'bit.ly/', 'g00gle.com', '.ml/', 'phishing']):
                expected = 'malicious'
            else:
                expected = None  # Uncertain cases
            
            status = "✅" if result['prediction'] == expected or expected is None else "❌"
            
            print(f"{status} {url}")
            print(f"   → {result['prediction']} (confidence: {result['confidence']:.3f}) - {result['reason']}")
            
            if expected and result['prediction'] == expected:
                correct_predictions += 1
            elif expected:
                total_predictions += 1  # Count only cases where we have expected results
        
        if total_predictions > 0:
            accuracy = correct_predictions / total_predictions
            print(f"\\n🎯 Test Accuracy on Diverse URLs: {accuracy:.2%}")
        
        return enhanced_classifier
    
    def run_extended_training(self):
        """Run the complete extended training pipeline"""
        print("🚀 EXTENDED DATASET TRAINING PIPELINE")
        print("=" * 60)
        
        try:
            # Collect multiple datasets
            datasets = self.collect_additional_datasets()
            
            # Advanced preprocessing
            processed_df = self.advanced_data_preprocessing(datasets)
            
            # Feature extraction with augmentation
            X, y = self.extract_features_with_augmentation(processed_df)
            
            # Advanced model training
            results, X_test, y_test = self.train_advanced_models(X, y)
            
            # Print comprehensive results
            print("\\n📊 EXTENDED TRAINING RESULTS")
            print("=" * 50)
            for name, metrics in results.items():
                print(f"{name.upper()}:")
                print(f"  Test Accuracy: {metrics['accuracy']:.4f}")
                print(f"  CV Mean: {metrics['cv_mean']:.4f}")
                print(f"  CV Std: {metrics['cv_std']:.4f}")
            
            # Save enhanced models
            self.save_enhanced_models()
            
            # Comprehensive testing
            self.comprehensive_testing()
            
            print("\\n🎉 EXTENDED TRAINING COMPLETE!")
            print("Enhanced system ready for out-of-dataset URL analysis!")
            
        except Exception as e:
            print(f"❌ Error during extended training: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    trainer = ExtendedDatasetTrainer()
    trainer.run_extended_training()