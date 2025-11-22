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
            subdomain = extracted.subdomain
            
            # Government and educational domains (very high trust)
            gov_edu_tlds = ['.gov', '.edu', '.ac.', '.edu.', '.gov.']
            for tld in gov_edu_tlds:
                if tld in url.lower():
                    return True, "Government/Educational domain"
            
            # Major legitimate patterns
            legitimate_patterns = {
                'legitimate_subdomains': ['www', 'api', 'docs', 'support', 'help', 'blog', 'news', 'cdn', 'static', 
                                        'shop', 'store', 'mail', 'email', 'portal', 'app', 'mobile', 'secure'],
                'legitimate_tlds': ['.org', '.net', '.co.uk', '.ca', '.de', '.fr', '.jp', '.au', '.co', '.io', 
                                   '.us', '.it', '.es', '.nl', '.br', '.in', '.ru', '.kr', '.sg'],
                'development_patterns': ['localhost', '127.0.0.1', 'dev.', 'staging.', 'test.', 'demo.', 'beta.'],
                'cdn_patterns': ['cdn.', 'assets.', 'static.', 'img.', 'media.', 'files.', 'images.', 'js.', 'css.'],
                'business_patterns': ['.com', '.biz', '.info', '.pro', '.store', '.shop', '.online', '.site']
            }
            
            # Check for development/testing patterns (benign in dev environments)
            for dev_pattern in legitimate_patterns['development_patterns']:
                if dev_pattern in url.lower():
                    return True, "Development/Testing environment"
            
            # Check for CDN/asset patterns
            for cdn_pattern in legitimate_patterns['cdn_patterns']:
                if (url.lower().startswith(f"https://{cdn_pattern}") or 
                    url.lower().startswith(f"http://{cdn_pattern}") or
                    subdomain.startswith(cdn_pattern.replace('.', ''))):
                    return True, "CDN/Asset delivery pattern"
            
            # Enhanced business legitimacy check
            if url.startswith('https://'):
                # Check for reasonable domain characteristics
                domain_clean = domain.lower().replace('-', '').replace('_', '')
                
                # Good signs: reasonable length, common TLD, no suspicious keywords
                good_length = 4 <= len(extracted.domain) <= 30
                common_tld = any(tld in domain.lower() for tld in legitimate_patterns['legitimate_tlds'] + 
                                legitimate_patterns['business_patterns'])
                no_suspicious_words = not any(word in domain.lower() for word in 
                                            ['phishing', 'malware', 'fake', 'scam', 'hack', 'virus', 'trojan'])
                
                # Check for legitimate subdomain patterns
                legitimate_subdomain = (subdomain == '' or subdomain == 'www' or 
                                      any(sub in subdomain for sub in legitimate_patterns['legitimate_subdomains']))
                
                # Alphanumeric domain (not just random characters)
                mostly_alpha = sum(c.isalpha() for c in extracted.domain) > len(extracted.domain) * 0.6
                
                if (good_length and common_tld and no_suspicious_words and 
                    legitimate_subdomain and mostly_alpha):
                    return True, "Legitimate business website pattern"
            
            # Check for well-formed email provider patterns
            email_providers = ['gmail', 'outlook', 'yahoo', 'hotmail', 'icloud', 'protonmail', 'zoho']
            if any(provider in domain.lower() for provider in email_providers):
                return True, "Email service provider"
            
            # Check for established technology companies not in trusted list
            tech_indicators = ['tech', 'software', 'cloud', 'data', 'digital', 'cyber', 'IT', 'systems']
            if (url.startswith('https://') and 
                any(indicator.lower() in domain.lower() for indicator in tech_indicators) and
                len(extracted.domain) < 20):
                return True, "Technology company pattern"
            
            return False, "No legitimate pattern detected"
            
        except:
            return False, "Pattern analysis failed"
    
    def detect_advanced_threats(self, url):
        """Advanced threat detection for URLs outside dataset"""
        try:
            extracted = tldextract.extract(url)
            domain = extracted.domain.lower()
            full_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            
            # Expanded typosquatting patterns for major sites
            typosquatting_patterns = {
                'paypal': ['paypai', 'paypaI', 'paypaII', 'payp4l', 'paypayl', 'paipal', 'pyppal', 'paypa1', 'paypall', 'paypaII', 'papyal', 'payp@l'],
                'google': ['goog1e', 'gooogle', 'googIe', 'g00gle', 'googel', 'gogle', 'g0ogle', 'googie', 'goog1le', 'gooqle'],
                'microsoft': ['microsft', 'microsooft', 'microsoftt', 'micr0soft', 'mikrosoft', 'microsofy', 'micosoft', 'microsof7'],
                'amazon': ['amazom', 'amazone', 'amazoon', 'am4zon', 'amazn', 'amazonn', 'amaz0n', 'amazom', 'ammazon'],
                'facebook': ['facebbok', 'faceebook', 'facbook', 'f4cebook', 'facebok', 'faceb00k', 'fac3book', 'facebookk'],
                'apple': ['appIe', 'aple', 'applee', 'app1e', 'appl3', 'app1le', 'appie', 'aplle'],
                'github': ['githup', 'githuub', 'g1thub', 'guthub', 'githib', 'githug', 'gith0b', 'gi7hub'],
                'twitter': ['twiter', 'twiteer', 'twittter', 'tw1tter', 'twiiter', 'twitt3r', 'twittr', 'twitteer'],
                'instagram': ['instagr4m', 'instagramm', 'inst4gram', 'instagam', 'instqgram', 'insragram'],
                'linkedin': ['linkedln', 'linkedin', 'linked1n', 'linkdin', 'linkedinn', 'linkedim'],
                'netflix': ['netf1ix', 'netflixx', 'netf1lix', 'ne7flix', 'netflx', 'netfl1x'],
                'spotify': ['spot1fy', 'spottify', 'sp0tify', 'spotfiy', 'spotifi', 'spottfy'],
                'dropbox': ['dr0pbox', 'dropb0x', 'dropboxx', 'dropb0x', 'drapbox', 'dropbax'],
                'adobe': ['ad0be', 'adobee', 'ad0bee', 'adope', 'adobo', 'adove']
            }
            
            # Check direct typosquatting matches
            for legit_domain, typos in typosquatting_patterns.items():
                if domain in typos:
                    return True, f"Typosquatting of {legit_domain}", 0.95
                    
            # Advanced character substitution detection
            suspicious_substitutions = {
                'o': ['0', 'ø', 'ο'], 'l': ['1', 'I', '|'], 'i': ['1', 'l', 'I'], 
                'a': ['@', 'α'], 'e': ['3', 'ε'], 's': ['$', '5'], 'g': ['9', 'q'],
                'm': ['n', 'rn'], 'u': ['v', 'μ'], 'c': ['e', '©'], 't': ['7', '+']
            }
            
            # Check for homograph attacks and character substitutions
            legit_sites = ['paypal', 'google', 'microsoft', 'amazon', 'facebook', 'apple', 'github', 
                          'twitter', 'instagram', 'linkedin', 'netflix', 'spotify', 'dropbox', 'adobe',
                          'yahoo', 'ebay', 'walmart', 'target', 'bestbuy', 'chase', 'wellsfargo']
            
            for site in legit_sites:
                if len(domain) == len(site):  # Same length suggests substitution
                    differences = sum(1 for a, b in zip(domain, site) if a != b)
                    if 1 <= differences <= 2:  # 1-2 character differences
                        return True, f"Character substitution attack targeting {site}", 0.90
                        
                # Check if domain contains the legitimate site name with additions
                if site in domain and domain != site:
                    extra_chars = domain.replace(site, '')
                    if len(extra_chars) <= 3:  # Short additions like numbers/symbols
                        return True, f"Domain spoofing of {site}", 0.85
            
            # Banking and financial institution patterns
            financial_keywords = ['bank', 'credit', 'loan', 'finance', 'payment', 'transfer', 'account', 
                                 'secure', 'verify', 'update', 'suspended', 'locked', 'confirm']
            financial_domains = ['chase', 'wellsfargo', 'bankofamerica', 'citi', 'capitalone', 'usbank']
            
            suspicious_financial = False
            for keyword in financial_keywords:
                if keyword in domain:
                    for fin_domain in financial_domains:
                        if fin_domain in domain and domain != fin_domain:
                            return True, f"Financial phishing targeting {fin_domain}", 0.90
                    suspicious_financial = True
            
            # Generic phishing patterns
            phishing_indicators = [
                'secure-', 'verify-', 'update-', 'suspended-', 'account-', 'billing-',
                'security-', 'alert-', 'warning-', 'urgent-', 'immediate-', 'action-',
                '-security', '-verify', '-update', '-login', '-account', '-billing'
            ]
            
            for indicator in phishing_indicators:
                if indicator in domain:
                    return True, f"Phishing pattern detected: {indicator}", 0.80
            
            # Cryptocurrency and tech scam patterns
            crypto_keywords = ['bitcoin', 'crypto', 'blockchain', 'wallet', 'mining', 'nft', 'defi']
            tech_scam_patterns = ['free-', 'win-', 'prize-', 'gift-', 'bonus-', 'earn-']
            
            for crypto in crypto_keywords:
                if crypto in domain:
                    for scam in tech_scam_patterns:
                        if scam in domain:
                            return True, f"Cryptocurrency scam pattern", 0.85
            
            return False, "No advanced threats detected", 0.0
            
        except:
            return False, "Advanced threat analysis failed", 0.0
            
    def detect_typosquatting(self, url):
        """Legacy method - now calls advanced threat detection"""
        is_threat, reason, confidence = self.detect_advanced_threats(url)
        return is_threat, reason
            
    def predict_url(self, url):
        """Enhanced prediction with comprehensive threat detection for out-of-dataset URLs"""
        try:
            # First check if it's a trusted domain (highest priority)
            if self.is_trusted_url(url):
                return {
                    'risk_level': 'Low',
                    'confidence': 95.0,
                    'explanation': 'Trusted domain override'
                }
            
            # Advanced threat detection (high priority)
            is_threat, threat_reason, threat_confidence = self.detect_advanced_threats(url)
            if is_threat:
                return {
                    'risk_level': 'High',
                    'confidence': threat_confidence * 100,
                    'explanation': threat_reason
                }
            
            # Check for legitimate patterns in non-trusted domains
            is_legit, legit_reason = self.is_legitimate_pattern(url)
            if is_legit:
                return {
                    'risk_level': 'Low',
                    'confidence': 85.0,
                    'explanation': f'Legitimate pattern: {legit_reason}'
                }
            
            # Enhanced malicious pattern detection
            url_lower = url.lower()
            extracted = tldextract.extract(url)
            domain = extracted.domain.lower()
            
            # IP address check (high threat)
            import re
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                return {
                    'risk_level': 'High',
                    'confidence': 90.0,
                    'explanation': 'Direct IP address URL (bypassing DNS)'
                }
            
            # Suspicious TLD check with expanded list
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download', 
                              '.work', '.party', '.stream', '.racing', '.review', '.science']
            if any(tld in url_lower for tld in suspicious_tlds):
                return {
                    'risk_level': 'High',
                    'confidence': 80.0,
                    'explanation': 'High-risk TLD commonly used by threat actors'
                }
            
            # Enhanced URL shortener detection
            shorteners = ['bit.ly/', 'tinyurl.com/', 't.co/', 'goo.gl/', 'ow.ly/', 'short.link/', 
                         'tiny.cc/', 'rb.gy/', 'cutt.ly/', 'is.gd/', 'buff.ly/', 'lnkd.in/']
            if any(short in url_lower for short in shorteners):
                return {
                    'risk_level': 'High',
                    'confidence': 70.0,
                    'explanation': 'URL shortener (potential redirect to malicious content)'
                }
            
            # Suspicious URL structure patterns
            suspicious_patterns = [
                (re.compile(r'https?://[^/]*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'), 'IP address in URL'),
                (re.compile(r'https?://[^/]*-[^/]*-[^/]*-[^/]*'), 'Excessive hyphens in domain'),
                (re.compile(r'https?://[^/]*\w{20,}'), 'Extremely long domain name'),
                (re.compile(r'https?://[^/]*[0-9]{4,}'), 'Many consecutive numbers in domain'),
            ]
            
            for pattern, reason in suspicious_patterns:
                if pattern.search(url):
                    return {
                        'risk_level': 'High',
                        'confidence': 75.0,
                        'explanation': f'Suspicious URL structure: {reason}'
                    }
            
            # Advanced keyword analysis for out-of-dataset threats
            malicious_keywords = {
                'phishing': ['secure', 'verify', 'update', 'suspended', 'locked', 'confirm', 'alert', 'warning', 'urgent'],
                'malware': ['download', 'free', 'crack', 'keygen', 'patch', 'hack', 'exploit'],
                'scam': ['prize', 'winner', 'congratulations', 'claim', 'bonus', 'reward', 'gift']
            }
            
            for category, keywords in malicious_keywords.items():
                keyword_count = sum(1 for keyword in keywords if keyword in domain)
                if keyword_count >= 2:  # Multiple suspicious keywords
                    return {
                        'risk_level': 'High',
                        'confidence': 80.0,
                        'explanation': f'Multiple {category} keywords detected'
                    }
                elif keyword_count == 1 and len(domain) < 15:  # Single keyword in short domain
                    return {
                        'risk_level': 'High',
                        'confidence': 70.0,
                        'explanation': f'Suspicious {category} keyword pattern'
                    }
            
            # Try ML model if available (fallback for edge cases)
            if self.model is None:
                self._try_load_model()
                
            if self.model:
                try:
                    features = self.feature_extractor.extract_url_features([url])
                    pred = self.model.predict(features)[0]
                    pred_proba = self.model.predict_proba(features)[0]
                    class_name = self.feature_extractor.label_encoder.inverse_transform([pred])[0]
                    
                    # For out-of-dataset URLs, be more conservative with ML predictions
                    ml_confidence = max(pred_proba)
                    if ml_confidence > 0.8:  # High confidence ML prediction
                        risk_level = 'High' if class_name in ['phishing', 'malware', 'defacement'] else 'Low'
                        return {
                            'risk_level': risk_level,
                            'confidence': ml_confidence * 100,
                            'explanation': 'High-confidence ML prediction'
                        }
                except:
                    pass  # Fall through to enhanced heuristics
            
            # Enhanced heuristic scoring for unknown URLs
            suspicious_score = 0
            legitimacy_score = 0
            
            # Domain characteristics analysis
            if len(domain) > 20:
                suspicious_score += 0.4
            elif 5 <= len(domain) <= 15:
                legitimacy_score += 0.3
                
            # Character composition analysis
            digit_ratio = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
            if digit_ratio > 0.3:
                suspicious_score += 0.4
            elif digit_ratio == 0:
                legitimacy_score += 0.2
                
            # Special character analysis
            special_char_count = sum(1 for c in domain if c in '-_.~')
            if special_char_count > 3:
                suspicious_score += 0.3
            elif special_char_count <= 1:
                legitimacy_score += 0.2
                
            # Protocol and structure analysis
            if url.startswith('https://'):
                legitimacy_score += 0.3
            else:
                suspicious_score += 0.4
                
            # Dictionary word analysis (simple heuristic)
            common_words = ['news', 'blog', 'shop', 'store', 'tech', 'company', 'service', 'group', 'online']
            if any(word in domain for word in common_words):
                legitimacy_score += 0.3
            
            # Final decision based on scoring
            final_score = suspicious_score - legitimacy_score
            
            if final_score > 0.5:
                return {
                    'risk_level': 'High',
                    'confidence': min(75.0, (0.5 + final_score) * 100),
                    'explanation': 'Heuristic analysis indicates suspicious characteristics'
                }
            elif final_score < -0.3:
                return {
                    'risk_level': 'Low',
                    'confidence': min(80.0, (0.6 + abs(final_score)) * 100),
                    'explanation': 'Heuristic analysis indicates legitimate characteristics'
                }
            else:
                # Neutral/unknown case - conservative approach
                return {
                    'risk_level': 'Low',
                    'confidence': 55.0,
                    'explanation': 'Insufficient indicators for threat classification'
                }
                    
        except Exception as e:
            return {
                'risk_level': 'Unknown',
                'confidence': 0.0,
                'explanation': f'Analysis error: {str(e)}'
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
    
    def load_model(self, model_path='enhanced_classifier.joblib'):
        """Load the trained model"""
        try:
            # If it's a specific file path, load it directly
            if model_path.endswith('.joblib'):
                loaded = joblib.load(model_path)
                if isinstance(loaded, dict):
                    # Enhanced classifier format
                    if 'models' in loaded:
                        self.models = loaded['models']
                    if 'scalers' in loaded:
                        self.scalers = loaded['scalers']
                    if 'feature_extractor' in loaded:
                        self.feature_extractor = loaded['feature_extractor']
                else:
                    # Single model format
                    self.model = loaded
                return True
            else:
                # Directory path - try to load individual files
                self.model = joblib.load(f'{model_path}/random_forest_model.joblib')
                self.feature_extractor = joblib.load(f'{model_path}/feature_extractor.joblib')
                return True
        except Exception as e:
            print(f"Model loading error: {e}")
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