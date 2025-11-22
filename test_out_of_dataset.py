#!/usr/bin/env python3
"""
Test the enhanced classifier with out-of-dataset URLs
"""

import joblib
from enhanced_classifier import EnhancedURLClassifier

def test_out_of_dataset_urls():
    """Test URLs that are likely not in the training dataset"""
    
    print("🧪 Testing Enhanced Classifier with Out-of-Dataset URLs")
    print("=" * 70)
    
    # Load the current enhanced classifier
    try:
        classifier = joblib.load('enhanced_classifier.joblib')
    except:
        print("Creating new enhanced classifier...")
        classifier = EnhancedURLClassifier()
    
    # Test URLs that are likely NOT in the original training datasets
    test_cases = [
        # Modern development platforms (likely not in old datasets)
        ("https://vercel.com/dashboard", "benign", "Modern hosting platform"),
        ("https://www.figma.com/files/recent", "benign", "Design platform"),
        ("https://discord.com/channels/@me", "benign", "Communication platform"),
        ("https://tailwindcss.com/docs", "benign", "CSS framework docs"),
        ("https://nextjs.org/learn", "benign", "Next.js documentation"),
        
        # Educational/Learning platforms
        ("https://www.khanacademy.org/math/algebra", "benign", "Educational platform"),
        ("https://leetcode.com/problems", "benign", "Coding practice"),
        ("https://www.coursera.org/learn/machine-learning", "benign", "Online course"),
        ("https://replit.com/@username/project", "benign", "Online IDE"),
        
        # Package managers and CDNs
        ("https://www.npmjs.com/package/react", "benign", "NPM package"),
        ("https://pypi.org/project/django/", "benign", "Python package"),
        ("https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/", "benign", "CDN resource"),
        
        # API endpoints (legitimate but might be flagged)
        ("https://api.github.com/users/octocat", "benign", "GitHub API"),
        ("https://jsonplaceholder.typicode.com/posts/1", "benign", "Test API"),
        ("https://httpbin.org/get", "benign", "HTTP testing service"),
        
        # Subdomain patterns that might be suspicious
        ("https://docs.example-company.com/guide", "unknown", "Corporate docs subdomain"),
        ("https://api.startup-platform.io/v1/auth", "unknown", "API endpoint"),
        ("https://cdn.new-service.net/assets/logo.png", "unknown", "CDN asset"),
        
        # Obvious malicious patterns
        ("http://192.168.1.100/malware.exe", "malicious", "IP address with executable"),
        ("https://paypaI.com/login", "malicious", "Typosquatting (capital i)"),
        ("http://fake-banking.tk/secure-login", "malicious", "Suspicious TLD"),
        ("http://bit.ly/definitely-not-suspicious", "malicious", "URL shortener"),
        
        # Edge cases
        ("https://localhost:3000/app", "benign", "Local development"),
        ("https://www.gov.uk/government/organisations", "benign", "Government site"),
        ("https://university.edu/student-portal", "benign", "Educational domain"),
    ]
    
    print("Testing URLs...")
    print()
    
    correct_predictions = 0
    total_with_expected = 0
    
    for url, expected, description in test_cases:
        result = classifier.predict_url(url)
        
        # Determine if prediction matches expectation
        predicted = result['prediction']
        confidence = result['confidence']
        reason = result['reason']
        
        if expected == "unknown":
            status = "ℹ️"  # Unknown expected result
        elif expected == predicted:
            status = "✅"
            correct_predictions += 1
            total_with_expected += 1
        elif (expected == "benign" and predicted in ["benign"]) or (expected == "malicious" and predicted in ["malicious", "phishing", "malware"]):
            status = "✅"
            correct_predictions += 1
            total_with_expected += 1
        else:
            status = "❌"
            total_with_expected += 1
        
        print(f"{status} {description}")
        print(f"   URL: {url}")
        print(f"   Expected: {expected} | Predicted: {predicted} (confidence: {confidence:.3f})")
        print(f"   Reason: {reason}")
        print()
    
    if total_with_expected > 0:
        accuracy = correct_predictions / total_with_expected
        print(f"🎯 Accuracy on Out-of-Dataset URLs: {accuracy:.2%} ({correct_predictions}/{total_with_expected})")
    
    print()
    print("🔍 Analysis Summary:")
    print("- Trusted domains should be classified as benign with high confidence")
    print("- Modern platforms not in training data should still be handled well")
    print("- Malicious patterns should be detected regardless of specific URLs")
    print("- Edge cases like localhost and .gov/.edu should be handled appropriately")

if __name__ == "__main__":
    test_out_of_dataset_urls()