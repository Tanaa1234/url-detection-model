#!/usr/bin/env python3
"""
Streamlit App Debugging - Test what's actually happening in the UI
"""

from enhanced_classifier import EnhancedURLClassifier
import sys

def test_ui_flow():
    """Test the exact flow that happens in the Streamlit UI"""
    print("🔍 DEBUGGING STREAMLIT UI PREDICTION FLOW")
    print("=" * 60)
    
    # Step 1: Load Enhanced Classifier (same as app.py)
    print("1. Loading Enhanced Classifier...")
    classifier = EnhancedURLClassifier()
    loaded = classifier.load_model('models')
    print(f"   ✅ Loaded: {loaded}")
    
    if not loaded:
        print("   ❌ FAILED TO LOAD CLASSIFIER")
        return
    
    # Step 2: Test URLs that should be HIGH RISK
    phishing_urls = [
        'paypaI.com',           # Typosquatting paypal  
        'goog1e.com',           # Typosquatting google
        'microsoft-security.tk', # Suspicious TLD
        'amazon-verify.ml',     # Suspicious TLD
    ]
    
    print("\n2. Testing PHISHING URLs (should be HIGH RISK):")
    for url in phishing_urls:
        result = classifier.predict_url(url)
        prediction = result['prediction'] 
        confidence = result['confidence']
        reason = result['reason']
        
        # This is what should show in the UI
        if prediction == 'phishing':
            risk_display = "🔴 HIGH RISK"
            color = "RED"
        else:
            risk_display = "🟢 LOW RISK" 
            color = "GREEN"
            
        print(f"   {url:<25} -> {risk_display} ({confidence:.3f})")
        print(f"      Reason: {reason}")
        print(f"      UI Color: {color}")
        
        if prediction != 'phishing':
            print(f"      ❌ WRONG! This should be HIGH RISK")
        else:
            print(f"      ✅ CORRECT")
        print()
    
    # Step 3: Test URLs that should be LOW RISK
    safe_urls = [
        'google.com',
        'paypal.com', 
        'microsoft.com',
        'amazon.com'
    ]
    
    print("3. Testing SAFE URLs (should be LOW RISK):")
    for url in safe_urls:
        result = classifier.predict_url(url)
        prediction = result['prediction']
        confidence = result['confidence'] 
        reason = result['reason']
        
        if prediction == 'benign':
            risk_display = "🟢 LOW RISK"
            color = "GREEN"
        else:
            risk_display = "🔴 HIGH RISK"
            color = "RED"
            
        print(f"   {url:<25} -> {risk_display} ({confidence:.3f})")
        print(f"      Reason: {reason}")
        print(f"      UI Color: {color}")
        
        if prediction != 'benign':
            print(f"      ❌ WRONG! This should be LOW RISK")
        else:
            print(f"      ✅ CORRECT")
        print()

def test_display_logic():
    """Test how predictions get converted to UI display"""
    print("4. TESTING UI DISPLAY LOGIC")
    print("=" * 60)
    
    # Simulate what happens in the Streamlit app
    test_predictions = {
        'Enhanced Classifier': {
            'prediction': 'phishing',
            'confidence': 0.9,
            'reason': 'Typosquatting of paypal'
        }
    }
    
    print("Sample prediction result:")
    print(f"  {test_predictions}")
    
    # This is the logic from app.py for displaying results
    for model_name, pred_data in test_predictions.items():
        prediction = pred_data['prediction']
        confidence = pred_data['confidence']
        
        print(f"\nHow this gets displayed in UI:")
        print(f"  Model: {model_name}")
        print(f"  Prediction: {prediction}")
        
        if prediction in ['phishing', 'malware', 'defacement']:
            print(f"  ✅ Should show: 🔴 HIGH RISK / RED")
        elif prediction == 'benign':
            print(f"  ✅ Should show: 🟢 LOW RISK / GREEN") 
        else:
            print(f"  ❓ Unknown prediction: {prediction}")

if __name__ == "__main__":
    test_ui_flow()
    test_display_logic()
    
    print("\n" + "=" * 60)
    print("🎯 NEXT STEPS:")
    print("   1. Open http://localhost:8503 in browser")
    print("   2. Test these exact URLs in the Streamlit interface:")
    print("      - paypaI.com (should be HIGH RISK/RED)")
    print("      - goog1e.com (should be HIGH RISK/RED)")  
    print("      - google.com (should be LOW RISK/GREEN)")
    print("   3. Enable Debug Mode to see raw predictions")
    print("   4. Click System Diagnostics to verify Enhanced Classifier loaded")
    print("   5. Ensure Force Enhanced Classifier checkbox is ON")
    print("\n   If results don't match what's shown above, there's a UI bug!")