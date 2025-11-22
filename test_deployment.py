#!/usr/bin/env python3
"""
Quick test script to verify the Streamlit Cloud deployment is working correctly.
Use this to test phishing URL detection after deployment updates.
"""

import requests
import json

# Test URLs that should be detected as phishing
PHISHING_TEST_URLS = [
    'paypaI.com',      # Typosquatting paypal
    'goog1e.com',      # Tyrosquatting google  
    'microsoft-security.tk',  # Suspicious TLD
    'paypal-verification.ml',  # Suspicious pattern
    'amazon-login.tk'   # Suspicious pattern
]

# Legitimate URLs that should be safe
SAFE_TEST_URLS = [
    'google.com',
    'paypal.com',
    'microsoft.com',
    'amazon.com',
    'github.com'
]

def test_local_enhanced_classifier():
    """Test the enhanced classifier locally"""
    print("🧪 Testing Local Enhanced Classifier...")
    print("=" * 50)
    
    try:
        from enhanced_classifier import EnhancedURLClassifier
        
        classifier = EnhancedURLClassifier()
        classifier.load_model('models')
        
        print("✅ Enhanced Classifier loaded successfully")
        
        print("\n🔴 Testing Phishing URLs (should be HIGH RISK):")
        for url in PHISHING_TEST_URLS:
            result = classifier.predict_url(url)
            risk = "🔴 HIGH RISK" if result['prediction'] == 'phishing' else "🟡 LOW RISK"
            print(f"  {url:<30} -> {risk} ({result['confidence']:.3f}) - {result['reason']}")
        
        print("\n🟢 Testing Safe URLs (should be LOW RISK):")
        for url in SAFE_TEST_URLS:
            result = classifier.predict_url(url)
            risk = "🟢 LOW RISK" if result['prediction'] == 'benign' else "🔴 HIGH RISK"
            print(f"  {url:<30} -> {risk} ({result['confidence']:.3f}) - {result['reason']}")
            
    except Exception as e:
        print(f"❌ Error testing local classifier: {e}")

def manual_deployment_test_instructions():
    """Print instructions for manual testing of the deployed app"""
    print("\n" + "=" * 70)
    print("📋 MANUAL DEPLOYMENT TEST INSTRUCTIONS")
    print("=" * 70)
    
    print("\n1. Open your Streamlit Cloud app:")
    print("   https://url-detection-model-tanaa1234.streamlit.app/")
    
    print("\n2. NEW FEATURES TO CHECK:")
    print("   ✅ '🔒 Force Enhanced Classifier' should be checked by default")
    print("   ✅ Look for '🛡️ Active Model: Enhanced Classifier (Recommended)' at top") 
    print("   ✅ Click '🔍 System Diagnostics' button to verify Enhanced Classifier loaded")
    
    print("\n3. Test these PHISHING URLs (should show HIGH RISK/RED):")
    for url in PHISHING_TEST_URLS:
        print(f"   ✅ Test: {url}")
    
    print("\n4. Test these SAFE URLs (should show LOW RISK/GREEN):")
    for url in SAFE_TEST_URLS:
        print(f"   ✅ Test: {url}")
    
    print("\n5. TROUBLESHOOTING:")
    print("   ✅ Enable 'Debug Mode' in sidebar to see detailed predictions")
    print("   ✅ Click 'System Diagnostics' to check Enhanced Classifier status")
    print("   ✅ Ensure '🔒 Force Enhanced Classifier' is checked")
    print("   ✅ Look for override messages like 'Enhanced Classifier Override'")
    
    print("\n6. If phishing URLs STILL show LOW RISK:")
    print("   ❌ This indicates a deeper issue with model file loading on Streamlit Cloud")
    print("   ❌ Check the System Diagnostics output for error messages")
    print("   ❌ Try refreshing the page completely (Ctrl+F5)")

if __name__ == "__main__":
    print("🔍 URL Detection Model - Deployment Test")
    print("=" * 50)
    
    # Test local classifier first
    test_local_enhanced_classifier()
    
    # Print manual test instructions
    manual_deployment_test_instructions()
    
    print("\n" + "=" * 70)
    print("🚀 NEXT STEPS:")
    print("=" * 70)
    print("1. Wait 2-3 minutes for Streamlit Cloud to update from GitHub")
    print("2. Follow the manual test instructions above")
    print("3. If issues persist, check Streamlit Cloud logs")
    print("4. The Enhanced Classifier should now be the default model")