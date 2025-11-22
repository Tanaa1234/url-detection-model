"""
Data preprocessing and feature extraction for URL classification
"""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
import tldextract
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import string

class URLFeatureExtractor:
    """Extract features from URLs for machine learning"""
    
    def __init__(self):
        self.label_encoder = LabelEncoder()
        
    def extract_url_features(self, url):
        """Extract comprehensive features from a single URL"""
        features = {}
        
        try:
            # Parse URL
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Basic URL properties
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed.netloc)
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query)
            features['fragment_length'] = len(parsed.fragment)
            
            # Trusted domain indicators  
            trusted_domains = {
                'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'microsoft.com',
                'apple.com', 'wikipedia.org', 'twitter.com', 'instagram.com', 'linkedin.com',
                'github.com', 'stackoverflow.com', 'reddit.com', 'ebay.com', 'netflix.com',
                'paypal.com', 'dropbox.com', 'adobe.com', 'yahoo.com', 'bing.com'
            }
            domain_name = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
            features['is_trusted_domain'] = 1 if domain_name in trusted_domains else 0
            
            # Domain features
            features['subdomain_length'] = len(extracted.subdomain)
            features['tld_length'] = len(extracted.suffix)
            features['domain_tokens'] = len(extracted.domain.split('.')) if extracted.domain else 0
            
            # Character counts
            features['digit_count'] = sum(c.isdigit() for c in url)
            features['letter_count'] = sum(c.isalpha() for c in url)
            features['special_char_count'] = sum(not c.isalnum() for c in url)
            features['uppercase_count'] = sum(c.isupper() for c in url)
            features['lowercase_count'] = sum(c.islower() for c in url)
            
            # Specific character counts
            features['dot_count'] = url.count('.')
            features['dash_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['slash_count'] = url.count('/')
            features['question_mark_count'] = url.count('?')
            features['equals_count'] = url.count('=')
            features['at_count'] = url.count('@')
            features['ampersand_count'] = url.count('&')
            features['percent_count'] = url.count('%')
            features['hash_count'] = url.count('#')
            features['semicolon_count'] = url.count(';')
            
            # Suspicious patterns
            features['has_ip'] = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0
            features['has_shortening'] = 1 if any(short in url.lower() for short in [
                'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'
            ]) else 0
            features['has_suspicious_tld'] = 1 if any(tld in extracted.suffix for tld in [
                'tk', 'ml', 'ga', 'cf'
            ]) else 0
            
            # Legitimate domain indicators
            common_tlds = {'com', 'org', 'net', 'edu', 'gov', 'mil'}
            features['has_common_tld'] = 1 if extracted.suffix in common_tlds else 0
            
            # Domain age indicators (longer domains often more trustworthy)
            features['domain_has_www'] = 1 if extracted.subdomain == 'www' else 0
            features['domain_is_simple'] = 1 if extracted.subdomain in ['', 'www'] else 0
            
            # Protocol and port
            features['is_https'] = 1 if parsed.scheme == 'https' else 0
            features['has_port'] = 1 if ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443') else 0
            
            # URL depth (number of directories)
            features['url_depth'] = len([x for x in parsed.path.split('/') if x])
            
            # Entropy of URL (measure of randomness)
            features['url_entropy'] = self._calculate_entropy(url)
            features['domain_entropy'] = self._calculate_entropy(extracted.domain) if extracted.domain else 0
            
            # Ratio features
            if len(url) > 0:
                features['digit_ratio'] = features['digit_count'] / len(url)
                features['letter_ratio'] = features['letter_count'] / len(url)
                features['special_char_ratio'] = features['special_char_count'] / len(url)
            else:
                features['digit_ratio'] = 0
                features['letter_ratio'] = 0
                features['special_char_ratio'] = 0
            
        except Exception as e:
            print(f"Error processing URL {url}: {e}")
            # Return default features in case of error
            for key in ['url_length', 'domain_length', 'path_length', 'query_length', 
                       'fragment_length', 'subdomain_length', 'tld_length', 'domain_tokens',
                       'digit_count', 'letter_count', 'special_char_count', 'uppercase_count',
                       'lowercase_count', 'dot_count', 'dash_count', 'underscore_count',
                       'slash_count', 'question_mark_count', 'equals_count', 'at_count',
                       'ampersand_count', 'percent_count', 'hash_count', 'semicolon_count',
                       'has_ip', 'has_shortening', 'has_suspicious_tld', 'is_https',
                       'has_port', 'url_depth', 'url_entropy', 'domain_entropy',
                       'digit_ratio', 'letter_ratio', 'special_char_ratio', 'is_trusted_domain',
                       'has_common_tld', 'domain_has_www', 'domain_is_simple']:
                features[key] = 0
        
        return features
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)
        return entropy
    
    def extract_features_from_dataframe(self, df):
        """Extract features from a pandas DataFrame"""
        print("Extracting features from URLs...")
        
        # Extract features for all URLs
        feature_list = []
        for idx, url in enumerate(df['url']):
            if idx % 10000 == 0:
                print(f"Processed {idx}/{len(df)} URLs")
            features = self.extract_url_features(url)
            feature_list.append(features)
        
        # Convert to DataFrame
        feature_df = pd.DataFrame(feature_list)
        
        # Add target variable
        feature_df['target'] = df['type'].values
        
        print(f"Feature extraction complete. Shape: {feature_df.shape}")
        return feature_df
    
    def prepare_data(self, df, test_size=0.2, random_state=42):
        """Prepare data for machine learning"""
        print("Preparing data for training...")
        
        # Extract features
        feature_df = self.extract_features_from_dataframe(df)
        
        # Separate features and target
        X = feature_df.drop('target', axis=1)
        y = feature_df['target']
        
        # Encode target labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=test_size, random_state=random_state, stratify=y_encoded
        )
        
        print(f"Training set size: {X_train.shape}")
        print(f"Test set size: {X_test.shape}")
        print(f"Feature columns: {list(X.columns)}")
        
        return X_train, X_test, y_train, y_test, X.columns.tolist()
    
    def get_class_names(self):
        """Get the class names after encoding"""
        return self.label_encoder.classes_
    
    def transform_single_url(self, url):
        """Transform a single URL for prediction"""
        features = self.extract_url_features(url)
        return pd.DataFrame([features])

def load_and_preprocess_data():
    """Load dataset and preprocess it"""
    import kagglehub
    
    # Download dataset
    print("Downloading dataset...")
    path = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
    
    # Load data
    csv_path = f"{path}/malicious_phish.csv"
    df = pd.read_csv(csv_path)
    
    print(f"Loaded dataset with {len(df)} rows")
    print(f"Target distribution:\n{df['type'].value_counts()}")
    
    return df

if __name__ == "__main__":
    # Test the feature extractor
    df = load_and_preprocess_data()
    
    # Sample a smaller subset for testing
    sample_df = df.sample(n=1000, random_state=42)
    
    # Extract features
    extractor = URLFeatureExtractor()
    X_train, X_test, y_train, y_test, feature_names = extractor.prepare_data(sample_df)
    
    print(f"\nClass names: {extractor.get_class_names()}")
    print("Feature extraction and preprocessing complete!")