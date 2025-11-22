#!/usr/bin/env python3
"""
Comprehensive deployment validation script for URL Detection Model
Tests both local Enhanced Classifier and provides cloud testing instructions
"""

import os
import sys
from pathlib import Path

def test_enhanced_classifier():
    """Test Enhanced Classifier functionality"""
    print("🧪 TESTING ENHANCED CLASSIFIER LOCALLY")
    print("=" * 60)
    
    try:
        from enhanced_classifier import EnhancedURLClassifier
        
        # Initialize classifier
        classifier = EnhancedURLClassifier()
        loaded = classifier.load_model('models')
        
        if not loaded:
            print("❌ Failed to load Enhanced Classifier models")
            return False
            
        print("✅ Enhanced Classifier loaded successfully")
        
        # Test phishing URLs (should be HIGH RISK)
        phishing_urls = [
            'paypaI.com',           # Typosquatting paypal
            'goog1e.com',           # Typosquatting google  
            'microsoft-security.tk', # Suspicious TLD
            'amazon-verify.ml',      # Suspicious pattern
            'facebook-login.cf'      # Suspicious pattern
        ]
        
        print("\n🔴 PHISHING URLs (should show HIGH RISK):")
        all_correct = True
        
        for url in phishing_urls:
            result = classifier.predict_url(url)
            is_phishing = result['prediction'] == 'phishing'
            status = "✅ CORRECT" if is_phishing else "❌ WRONG"
            risk = "HIGH RISK" if is_phishing else "LOW RISK"
            
            print(f"  {url:<25} -> {risk:<9} ({result['confidence']:.3f}) {status}")
            print(f"    Reason: {result['reason']}")
            
            if not is_phishing:
                all_correct = False
        
        # Test safe URLs (should be LOW RISK)
        safe_urls = ['google.com', 'paypal.com', 'microsoft.com', 'amazon.com', 'facebook.com']
        
        print("\n🟢 SAFE URLs (should show LOW RISK):")
        for url in safe_urls:
            result = classifier.predict_url(url)
            is_safe = result['prediction'] == 'benign'
            status = "✅ CORRECT" if is_safe else "❌ WRONG"
            risk = "LOW RISK" if is_safe else "HIGH RISK"
            
            print(f"  {url:<25} -> {risk:<9} ({result['confidence']:.3f}) {status}")
            print(f"    Reason: {result['reason']}")
            
            if not is_safe:
                all_correct = False
        
        return all_correct
        
    except Exception as e:
        print(f"❌ Error testing Enhanced Classifier: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_file_structure():
    """Check that all required files exist"""
    print("\n📁 CHECKING FILE STRUCTURE")
    print("=" * 60)
    
    required_files = [
        'enhanced_classifier.py',
        'enhanced_classifier.joblib',
        'app.py',
        'requirements.txt',
        'models/random_forest_model.joblib',
        'models/xgboost_model.joblib',
        'models/knn_model.joblib',
        'models/svm_model.joblib',
        'feature_extractor.joblib'
    ]
    
    all_exist = True
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING!")
            all_exist = False
    
    return all_exist

def print_local_test_instructions():
    """Print instructions for testing the local Streamlit app"""
    print("\n🖥️  LOCAL STREAMLIT APP TESTING")
    print("=" * 60)
    
    print("1. Open: http://localhost:8501")
    print("\n2. In the sidebar, verify:")
    print("   ✅ '🔒 Force Enhanced Classifier' is CHECKED")
    print("   ✅ 'Enhanced Classifier (Recommended)' is selected")
    print("   ✅ Click '🔍 System Diagnostics' - should show Enhanced Classifier loaded")
    
    print("\n3. Test these PHISHING URLs (should show RED/HIGH RISK):")
    phishing_urls = ['paypaI.com', 'goog1e.com', 'microsoft-security.tk']
    for url in phishing_urls:
        print(f"   🔴 {url}")
    
    print("\n4. Test these SAFE URLs (should show GREEN/LOW RISK):")
    safe_urls = ['google.com', 'paypal.com', 'microsoft.com']
    for url in safe_urls:
        print(f"   🟢 {url}")
    
    print("\n5. Enable 'Debug Mode' to see detailed prediction info")

def print_cloud_comparison_instructions():
    """Print instructions for comparing cloud deployment"""
    print("\n☁️  STREAMLIT CLOUD TESTING")
    print("=" * 60)
    
    print("1. Open: https://url-detection-model-tanaa1234.streamlit.app/")
    print("\n2. Compare with local results:")
    print("   ✅ Same sidebar options should be available")
    print("   ✅ System Diagnostics should show same file status")
    print("   ✅ Same URLs should give same risk classifications")
    
    print("\n3. If cloud results differ from local:")
    print("   🔍 Check System Diagnostics output")
    print("   🔍 Enable Debug Mode to see raw predictions")
    print("   🔍 Verify Enhanced Classifier is being used")
    
    print("\n4. Common cloud deployment issues:")
    print("   ❌ Enhanced Classifier not loading -> Check diagnostics")
    print("   ❌ Wrong model selected -> Force Enhanced Classifier checkbox")
    print("   ❌ File missing -> Check if files deployed correctly")

def main():
    """Run all validation tests"""
    print("🚀 URL DETECTION MODEL - DEPLOYMENT VALIDATION")
    print("=" * 60)
    print(f"📂 Working Directory: {os.getcwd()}")
    print(f"🐍 Python: {sys.executable}")
    
    # Test file structure
    files_ok = check_file_structure()
    
    # Test Enhanced Classifier
    classifier_ok = test_enhanced_classifier()
    
    # Print testing instructions
    print_local_test_instructions()
    print_cloud_comparison_instructions()
    
    # Summary
    print("\n📊 VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Files Structure: {'✅ PASS' if files_ok else '❌ FAIL'}")
    print(f"Enhanced Classifier: {'✅ PASS' if classifier_ok else '❌ FAIL'}")
    
    if files_ok and classifier_ok:
        print("\n🎯 LOCAL SYSTEM: READY FOR TESTING")
        print("   → Open http://localhost:8501 to test the UI")
        print("   → Compare results with cloud deployment")
    else:
        print("\n⚠️  ISSUES DETECTED - Fix before proceeding")
    
    return files_ok and classifier_ok

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)