"""
Demo script to test the URL Detection System
"""

from model_trainer import URLClassifierTrainer
from data_preprocessing import URLFeatureExtractor
import os

def demo_url_detection():
    """Demonstrate the URL detection system"""
    print("🔍 URL MALICIOUSNESS DETECTION SYSTEM DEMO")
    print("=" * 60)
    
    # Check if models exist
    if not os.path.exists('models/random_forest_model.joblib'):
        print("❌ No trained models found!")
        print("Please run: python main.py --action train")
        return
    
    # Load trained models
    print("📚 Loading trained models...")
    trainer = URLClassifierTrainer()
    trainer.load_models('models')
    print("✅ Models loaded successfully!")
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://www.amazon.com",
        "http://bit.ly/suspiciouslink",
        "http://192.168.1.1/admin",
        "https://secure-bank-login.tk/login.php",
        "http://www.example-phishing.com/verify-account",
        "https://malware-download.exe.com",
        "https://www.wikipedia.org",
        "https://stackoverflow.com"
    ]
    
    print(f"\n🧪 Testing {len(test_urls)} URLs...")
    print("=" * 60)
    
    for i, url in enumerate(test_urls, 1):
        print(f"\n[{i}] Testing: {url}")
        print("-" * 50)
        
        try:
            predictions = trainer.predict_url(url)
            
            # Get majority vote
            pred_classes = [pred['prediction'] for pred in predictions.values() 
                          if pred['prediction'] != 'Error']
            
            if pred_classes:
                majority_prediction = max(set(pred_classes), key=pred_classes.count)
                risk_level = "🚨 HIGH RISK" if majority_prediction in ['phishing', 'malware', 'defacement'] else "✅ LOW RISK"
                
                print(f"Overall Assessment: {risk_level}")
                print(f"Majority Classification: {majority_prediction.upper()}")
                print("\nIndividual Model Results:")
                
                for model_name, pred_data in predictions.items():
                    confidence = pred_data['confidence']
                    prediction = pred_data['prediction']
                    conf_str = f"{confidence:.3f}" if confidence else "N/A"
                    print(f"  • {model_name:<15}: {prediction:<12} (confidence: {conf_str})")
            else:
                print("❌ Error analyzing URL")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("✅ Demo completed!")
    print("\n🌐 To use the web interface, run:")
    print("   streamlit run app.py")
    print("\n📊 To view this demo again, run:")
    print("   python demo.py")

if __name__ == "__main__":
    demo_url_detection()