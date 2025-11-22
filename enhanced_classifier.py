"""
Enhanced URL classifier with trusted domain override
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from data_preprocessing import URLFeatureExtractor
import tldextract

class EnhancedURLClassifier:
    """Enhanced classifier with trusted domain logic"""
    
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.model = None
        self.trusted_domains = {
            # Search engines & major tech
            'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com', 'yandex.com',
            
            # Social media platforms
            'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'reddit.com',
            'youtube.com', 'tiktok.com', 'snapchat.com', 'discord.com', 'twitch.tv',
            
            # Major technology companies
            'microsoft.com', 'apple.com', 'amazon.com', 'adobe.com', 'oracle.com', 'ibm.com',
            
            # Development & coding platforms
            'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'dev.to',
            'hackernews.com', 'codepen.io', 'jsfiddle.net', 'repl.it', 'codesandbox.io',
            
            # Cloud services & productivity
            'dropbox.com', 'onedrive.live.com', 'icloud.com', 'box.com', 'drive.google.com',
            'notion.so', 'trello.com', 'slack.com', 'zoom.us', 'teams.microsoft.com',
            
            # E-commerce & payments
            'ebay.com', 'etsy.com', 'shopify.com', 'paypal.com', 'stripe.com', 'square.com',
            'walmart.com', 'target.com', 'bestbuy.com', 'costco.com', 'alibaba.com',
            
            # Entertainment & media
            'netflix.com', 'hulu.com', 'disney.com', 'spotify.com', 'soundcloud.com',
            'vimeo.com', 'dailymotion.com', 'twitch.tv', 'steam.com', 'epic.com',
            
            # Educational platforms
            'coursera.org', 'edx.org', 'udemy.com', 'khanacademy.org', 'duolingo.com',
            'skillshare.com', 'pluralsight.com', 'codecademy.com', 'freecodecamp.org',
            
            # News & information
            'wikipedia.org', 'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com',
            'theguardian.com', 'npr.org', 'wsj.com', 'forbes.com', 'techcrunch.com',
            
            # Development tools & languages
            'python.org', 'nodejs.org', 'golang.org', 'rust-lang.org', 'java.com',
            'mozilla.org', 'w3.org', 'whatwg.org', 'ecma-international.org',
            'replit.com', 'codepen.io', 'jsfiddle.net', 'codesandbox.io',
            
            # Package managers & CDNs
            'npmjs.com', 'pypi.org', 'rubygems.org', 'nuget.org', 'packagist.org',
            'jsdelivr.net', 'unpkg.com', 'cdnjs.com', 'bootstrapcdn.com',
            
            # Cloud providers & hosting
            'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com', 'heroku.com',
            'vercel.com', 'netlify.com', 'digitalocean.com', 'linode.com', 'vultr.com',
            
            # Operating systems & browsers
            'ubuntu.com', 'redhat.com', 'debian.org', 'archlinux.org', 'freebsd.org',
            'chrome.google.com', 'firefox.com', 'opera.com', 'brave.com', 'edge.microsoft.com',
            
            # Design & productivity tools
            'figma.com', 'sketch.com', 'adobe.com', 'canva.com', 'miro.com',
            'airtable.com', 'asana.com', 'monday.com', 'atlassian.com', 'jetbrains.com'
        }
        
    def is_trusted_url(self, url):
        """Check if URL is from a trusted domain"""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
            
            # Check exact match
            if domain in self.trusted_domains:
                return True
                
            # Check if it's a subdomain of trusted domain
            for trusted in self.trusted_domains:
                if domain.endswith('.' + trusted) or domain == trusted:
                    return True
                    
            return False
        except:
            return False
    
    def is_legitimate_pattern(self, url):
        """Check for legitimate URL patterns even if not in trusted domains"""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
            
            # Government and educational domains
            gov_edu_tlds = ['.gov', '.edu', '.ac.', '.edu.', '.gov.']
            for tld in gov_edu_tlds:
                if tld in url.lower():
                    return True, "Government/Educational domain"
            
            # Major country code TLDs with legitimate patterns
            legitimate_patterns = {
                'legitimate_subdomains': ['www', 'api', 'docs', 'support', 'help', 'blog', 'news', 'cdn', 'static'],
                'legitimate_tlds': ['.org', '.net', '.co.uk', '.ca', '.de', '.fr', '.jp', '.au'],
                'development_patterns': ['localhost', '127.0.0.1', 'dev.', 'staging.', 'test.'],
                'cdn_patterns': ['cdn.', 'assets.', 'static.', 'img.', 'media.', 'files.']
            }
            
            # Check for development/testing patterns (should be benign in dev environments)
            for dev_pattern in legitimate_patterns['development_patterns']:
                if dev_pattern in url.lower():
                    return True, "Development/Testing environment"
            
            # Check for CDN patterns
            for cdn_pattern in legitimate_patterns['cdn_patterns']:
                if url.lower().startswith(f"https://{cdn_pattern}") or url.lower().startswith(f"http://{cdn_pattern}"):
                    return True, "CDN/Asset delivery pattern"
            
            # Check for HTTPS + legitimate TLD + reasonable length
            if (url.startswith('https://') and 
                any(tld in domain.lower() for tld in legitimate_patterns['legitimate_tlds']) and
                len(domain) < 50 and  # Reasonable domain length
                '.' in domain and  # Has TLD
                not any(suspicious in domain.lower() for suspicious in ['phishing', 'malware', 'fake', 'scam'])):
                return True, "Legitimate HTTPS pattern"
            
            return False, "No legitimate pattern detected"
            
        except:
            return False, "Pattern analysis failed"
    
    def detect_typosquatting(self, url):
        """Detect typosquatting patterns in URLs"""
        try:
            extracted = tldextract.extract(url)
            domain = extracted.domain.lower()
            
            # Common typosquatting patterns for major sites
            typosquatting_patterns = {
                'paypal': ['paypai', 'paypaI', 'paypaII', 'payp4l', 'paypayl', 'paipal', 'pyppal', 'paypa1', 'paypall'],
                'google': ['goog1e', 'gooogle', 'googIe', 'g00gle', 'googel', 'gogle'],
                'microsoft': ['microsft', 'microsooft', 'microsoftt', 'micr0soft', 'mikrosoft'],
                'amazon': ['amazom', 'amazone', 'amazoon', 'am4zon', 'amazn', 'amazonn'],
                'facebook': ['facebbok', 'faceebook', 'facbook', 'f4cebook', 'facebok'],
                'apple': ['appIe', 'aple', 'applee', 'app1e', 'appl3'],
                'github': ['githup', 'githuub', 'g1thub', 'guthub', 'githib'],
                'twitter': ['twiter', 'twiteer', 'twittter', 'tw1tter', 'twiiter']
            }
            
            # Check if domain matches typosquatting patterns
            for legit_domain, typos in typosquatting_patterns.items():
                if domain in typos:
                    return True, f"Typosquatting of {legit_domain}"
                    
            # Generic suspicious patterns
            suspicious_chars = ['0', '1', 'I', 'l']
            legit_sites = ['paypal', 'google', 'microsoft', 'amazon', 'facebook', 'apple', 'github', 'twitter']
            
            for site in legit_sites:
                if site in domain and domain != site:
                    # Check for character substitutions
                    for char in suspicious_chars:
                        if char in domain and char not in site:
                            return True, f"Suspicious character substitution in {site}-like domain"
                            
            return False, "No typosquatting detected"
            
        except:
            return False, "Typosquatting analysis failed"
            
    def predict_url(self, url):
        """Enhanced prediction with trusted domain override"""
        try:
            # First check if it's a trusted domain
            if self.is_trusted_url(url):
                return {
                    'prediction': 'benign',
                    'confidence': 0.95,
                    'reason': 'Trusted domain override'
                }
            
            # Check for typosquatting first (high priority)
            is_typo, typo_reason = self.detect_typosquatting(url)
            if is_typo:
                return {
                    'prediction': 'phishing',
                    'confidence': 0.90,
                    'reason': typo_reason
                }
            
            # Check for legitimate patterns in non-trusted domains
            is_legit, legit_reason = self.is_legitimate_pattern(url)
            if is_legit:
                return {
                    'prediction': 'benign',
                    'confidence': 0.85,
                    'reason': f'Legitimate pattern: {legit_reason}'
                }
            
            # Check for obvious malicious patterns
            url_lower = url.lower()
            
            # IP address check
            import re
            if re.search(r'http://\d+\.\d+\.\d+\.\d+', url):
                return {
                    'prediction': 'malware',
                    'confidence': 0.90,
                    'reason': 'IP address URL'
                }
            
            # Suspicious TLD check
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
            if any(tld in url_lower for tld in suspicious_tlds):
                return {
                    'prediction': 'phishing',
                    'confidence': 0.80,
                    'reason': 'Suspicious TLD'
                }
            
            # URL shortener check (be more specific to avoid false positives)
            shorteners = ['bit.ly/', 'tinyurl.com/', 't.co/', 'goo.gl/', 'ow.ly/', 'short.link/', 'tiny.cc/']
            if any(short in url_lower for short in shorteners):
                return {
                    'prediction': 'phishing',
                    'confidence': 0.75,
                    'reason': 'URL shortener'
                }
            
            # Try to load and use ML model if available
            if self.model is None:
                self._try_load_model()
                
            if self.model:
                try:
                    features = self.feature_extractor.transform_single_url(url)
                    pred = self.model.predict(features)[0]
                    pred_proba = self.model.predict_proba(features)[0]
                    class_name = self.feature_extractor.label_encoder.inverse_transform([pred])[0]
                    
                    return {
                        'prediction': class_name,
                        'confidence': max(pred_proba),
                        'reason': 'ML model prediction'
                    }
                except:
                    pass  # Fall through to heuristics
            
            # Enhanced heuristic fallback
            # Enhanced fallback heuristics
            extracted = tldextract.extract(url)
            domain = extracted.domain.lower()
            
            # Check for suspicious domain characteristics
            suspicious_score = 0
            
            # Long domain names are often suspicious
            if len(domain) > 15:
                suspicious_score += 0.3
                
            # Multiple numbers in domain
            if sum(c.isdigit() for c in domain) > 2:
                suspicious_score += 0.4
                
            # Excessive hyphens
            if domain.count('-') > 2:
                suspicious_score += 0.3
                
            # Suspicious keywords
            suspicious_keywords = ['secure', 'verify', 'update', 'login', 'bank', 'paypal', 'microsoft']
            if any(keyword in domain for keyword in suspicious_keywords):
                suspicious_score += 0.5
                
            # Non-HTTPS adds suspicion
            if not url.startswith('https://'):
                suspicious_score += 0.2
                
            if suspicious_score > 0.5:
                return {
                    'prediction': 'phishing',
                    'confidence': min(0.8, 0.5 + suspicious_score),
                    'reason': 'Suspicious domain characteristics'
                }
            else:
                return {
                    'prediction': 'benign',
                    'confidence': max(0.4, 0.8 - suspicious_score),
                    'reason': 'Heuristic analysis'
                }
                    
        except Exception as e:
            return {
                'prediction': 'unknown',
                'confidence': 0.0,
                'reason': f'Error: {str(e)}'
            }
                
    def _try_load_model(self):
        """Try to load available ML models"""
        try:
            model_files = ['random_forest_model.joblib', 'xgboost_model.joblib', 'knn_model.joblib']
            for model_file in model_files:
                if os.path.exists(model_file):
                    self.model = joblib.load(model_file)
                    break
        except Exception:
            pass
    
    def load_model(self, models_dir='models'):
        """Load the trained model"""
        try:
            self.model = joblib.load(f'{models_dir}/random_forest_model.joblib')
            self.feature_extractor = joblib.load(f'{models_dir}/feature_extractor.joblib')
            return True
        except:
            return False

def create_enhanced_classifier():
    """Create and save enhanced classifier"""
    print("🚀 Creating Enhanced URL Classifier with Trusted Domain Override")
    print("="*70)
    
    classifier = EnhancedURLClassifier()
    
    # Try to load existing model
    if classifier.load_model():
        print("✅ Loaded existing ML model")
    else:
        print("⚠️  No ML model found, using heuristic-based classification")
    
    # Test on various URLs
    test_urls = [
        # Trusted domains
        'https://www.google.com',
        'https://github.com',
        'https://www.amazon.com',
        'https://docs.google.com/document/123',
        'https://www.youtube.com/watch?v=abc',
        
        # Potentially malicious
        'http://192.168.1.1/malware.exe',
        'http://fake-bank.tk/login.php',
        'http://bit.ly/suspicious123',
        'https://phishing-site.ml/secure/',
        
        # Regular websites
        'https://www.example.com',
        'http://www.news-site.org/article',
        'https://shop.smallbusiness.net'
    ]
    
    print("\nTesting Enhanced Classifier:")
    print("-" * 70)
    
    for url in test_urls:
        result = classifier.predict_url(url)
        status = "✅" if result['prediction'] == 'benign' else "⚠️" if result['prediction'] in ['phishing', 'malware', 'defacement'] else "❓"
        
        print(f"{status} {url}")
        print(f"   → {result['prediction']} (confidence: {result['confidence']:.3f}) - {result['reason']}")
        print()
    
    # Save the enhanced classifier
    joblib.dump(classifier, 'models/enhanced_classifier.joblib')
    print("✅ Enhanced classifier saved to models/enhanced_classifier.joblib")
    
    return classifier

if __name__ == "__main__":
    classifier = create_enhanced_classifier()
    
    print("\n" + "="*70)
    print("🎉 ENHANCED URL CLASSIFIER READY!")
    print("="*70)
    print("✅ Trusted domains will always be classified as safe")
    print("✅ Suspicious patterns are detected with high confidence")
    print("✅ ML model provides backup classification for edge cases")
    print("✅ System is now much more reliable for real-world use")