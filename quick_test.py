#!/usr/bin/env python3
"""
Quick Cloud Deployment Test - Copy and paste these URLs into both apps
"""

print("🔗 QUICK TEST URLs")
print("="*50)

print("\n📋 Copy these PHISHING URLs (should show HIGH RISK/RED):")
phishing_urls = [
    "paypaI.com",
    "goog1e.com", 
    "microsoft-security.tk"
]

for url in phishing_urls:
    print(f"   {url}")

print("\n📋 Copy these SAFE URLs (should show LOW RISK/GREEN):")
safe_urls = [
    "google.com",
    "paypal.com",
    "microsoft.com"
]

for url in safe_urls:
    print(f"   {url}")

print("\n🌐 TEST BOTH APPS:")
print("   LOCAL:  http://localhost:8501")
print("   CLOUD:  https://url-detection-model-tanaa1234.streamlit.app/")

print("\n✅ WHAT TO CHECK:")
print("   1. Force Enhanced Classifier checkbox is ON")
print("   2. System Diagnostics shows Enhanced Classifier loaded")
print("   3. Phishing URLs show HIGH RISK (red)")
print("   4. Safe URLs show LOW RISK (green)")
print("   5. Enable Debug Mode to see detailed reasons")

print("\n🚨 IF CLOUD SHOWS WRONG RESULTS:")
print("   → Click 'System Diagnostics' and compare with local")
print("   → Check if Enhanced Classifier is actually loaded")
print("   → Try refreshing the page (Ctrl+F5)")
print("   → Ensure 'Force Enhanced Classifier' is checked")