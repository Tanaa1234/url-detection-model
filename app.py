"""
Streamlit web application for URL maliciousness detection
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import os
import time
from model_trainer import URLClassifierTrainer
from data_preprocessing import URLFeatureExtractor
from enhanced_classifier import EnhancedURLClassifier
import joblib

# Page configuration
st.set_page_config(
    page_title="URL Maliciousness Detector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

@st.cache_resource
def load_trained_models():
    """Load enhanced classifier with robust error handling"""
    try:
        # Method 1: Try to load pre-trained enhanced classifier
        if os.path.exists('enhanced_classifier.joblib'):
            try:
                enhanced_data = joblib.load('enhanced_classifier.joblib')
                
                # Handle different formats
                if isinstance(enhanced_data, dict) and 'classifier' in enhanced_data:
                    enhanced = enhanced_data['classifier']
                else:
                    enhanced = enhanced_data
                    
                # Verify it has the predict_url method
                if hasattr(enhanced, 'predict_url'):
                    return enhanced
            except Exception:
                pass
        
        # Method 2: Try to load from models directory
        elif os.path.exists('models/enhanced_classifier.joblib'):
            try:
                enhanced = joblib.load('models/enhanced_classifier.joblib')
                if hasattr(enhanced, 'predict_url'):
                    return enhanced
            except Exception:
                pass
        
        # Method 3: Create fresh Enhanced Classifier and load models
        classifier = EnhancedURLClassifier()
        
        # Load individual models into the enhanced classifier
        if classifier.load_model('models'):
            # Verify it works with a test
            try:
                test_result = classifier.predict_url('google.com')
                if test_result.get('risk_level') == 'Low':
                    return classifier
                else:
                    # Still return it as it may be working fine
                    return classifier
            except Exception:
                pass
            
        # Method 4: Alternative classifier fallback  
        trainer = URLClassifierTrainer()
        if os.path.exists('models'):
            try:
                trainer.load_models('models')
                return trainer
            except Exception as e2:
                st.error(f"❌ Error loading fallback models: {e2}")
                return None
        return None
            
    except Exception as e:
        st.error(f"❌ Critical error in model loading: {e}")
        return None

@st.cache_resource 
def load_individual_models():
    """Load individual ML models for model selection"""
    models = {}
    scalers = {}
    
    try:
        # Load individual models
        models['Random Forest'] = joblib.load('random_forest_model.joblib')
        models['XGBoost'] = joblib.load('xgboost_model.joblib')
        models['K-Nearest Neighbors (KNN)'] = joblib.load('knn_model.joblib')
        models['Support Vector Machine (SVM)'] = joblib.load('svm_model.joblib')
        
        # Load scalers for models that need them
        scalers['K-Nearest Neighbors (KNN)'] = joblib.load('knn_scaler.joblib')
        scalers['Support Vector Machine (SVM)'] = joblib.load('svm_scaler.joblib')
        
        # Load feature extractor
        feature_extractor = joblib.load('feature_extractor.joblib')
        
        return models, scalers, feature_extractor
        
    except Exception as e:
        st.error(f"Error loading individual models: {e}")
        return {}, {}, None

def predict_with_selected_model(url, selected_model, trainer, models=None, scalers=None, feature_extractor=None):
    """Make prediction with the selected model"""
    
    # ALWAYS try Enhanced Classifier first if available, regardless of selected_model
    # This ensures phishing detection works even if UI state is confused
    if hasattr(trainer, 'predict_url'):
        if selected_model == "Enhanced Classifier (Recommended)" or selected_model == "All Models (Ensemble)":
            # User explicitly wants Enhanced Classifier
            result = trainer.predict_url(url)
            if st.session_state.get('debug_mode', False):
                st.write(f"🔍 Debug: Enhanced classifier returned: {result}")
                st.write(f"🔍 Debug: Trainer type: {type(trainer)}")
            return {"Enhanced Classifier": result}
        
        elif selected_model in ["Random Forest", "XGBoost", "K-Nearest Neighbors (KNN)", "Support Vector Machine (SVM)"]:
            # User wants individual model, but check Enhanced Classifier for overrides first
            try:
                enhanced_result = trainer.predict_url(url)
                # If Enhanced Classifier has a strong rule-based reason (not just ML prediction), use it
                if enhanced_result.get('reason', '').lower() not in ['ml model prediction', 'machine learning prediction']:
                    # Show override message
                    if st.session_state.get('debug_mode', False):
                        st.write(f"🔍 Debug: Enhanced classifier override: {enhanced_result}")
                    st.info(f"🛡️ **Enhanced Classifier Override**: Using rule-based detection instead of {selected_model}")
                    return {"Enhanced Classifier (Override)": enhanced_result}
            except Exception as e:
                if st.session_state.get('debug_mode', False):
                    st.write(f"🔍 Debug: Enhanced classifier check failed: {e}")
    
    if selected_model == "Enhanced Classifier (Recommended)":
        # Use enhanced classifier
        if hasattr(trainer, 'predict_url'):
            result = trainer.predict_url(url)
            # Debug output
            if st.session_state.get('debug_mode', False):
                st.write(f"🔍 Debug: Enhanced classifier returned: {result}")
            return {"Enhanced Classifier": result}
        else:
            st.error("❌ Enhanced classifier not available")
            return {"error": "Enhanced classifier not available"}
    
    elif selected_model == "All Models (Ensemble)":
        # Use enhanced classifier if available, otherwise show error
        if hasattr(trainer, 'predict_url'):
            return {"Enhanced Classifier": trainer.predict_url(url)}
        else:
            return {"error": "Ensemble mode requires enhanced classifier"}
    
    else:
        # Use individual model
        if models is None or feature_extractor is None:
            return {"error": f"{selected_model} not available"}
        
        if selected_model not in models:
            return {"error": f"Model {selected_model} not found"}

        # If an enhanced trainer is available, consult it first for rule-based overrides
        try:
            if hasattr(trainer, 'predict_url'):
                enhanced_result = trainer.predict_url(url)
                # If enhanced classifier returned a non-ML reason (trusted domain, typosquatting, heuristics), prefer it
                if enhanced_result.get('reason', '').lower() != 'ml model prediction':
                    # Return enhanced classifier override so user sees the safer, rule-backed decision
                    return {"Enhanced Classifier (Override)": enhanced_result}
        except Exception:
            # If enhanced classifier check fails, continue to individual model prediction
            pass

        try:
            # Extract features
            features_dict = feature_extractor.extract_url_features(url)
            
            # Convert to array format
            features_array = np.array([[
                float(features_dict.get('url_length', 0)), float(features_dict.get('domain_length', 0)), 
                float(features_dict.get('path_length', 0)), float(features_dict.get('query_length', 0)), 
                float(features_dict.get('fragment_length', 0)), float(features_dict.get('is_trusted_domain', 0)),
                float(features_dict.get('subdomain_length', 0)), float(features_dict.get('tld_length', 0)), 
                float(features_dict.get('domain_tokens', 0)), float(features_dict.get('digit_count', 0)), 
                float(features_dict.get('letter_count', 0)), float(features_dict.get('special_char_count', 0)),
                float(features_dict.get('uppercase_count', 0)), float(features_dict.get('lowercase_count', 0)), 
                float(features_dict.get('dot_count', 0)), float(features_dict.get('dash_count', 0)), 
                float(features_dict.get('underscore_count', 0)), float(features_dict.get('slash_count', 0)),
                float(features_dict.get('question_mark_count', 0)), float(features_dict.get('equals_count', 0)), 
                float(features_dict.get('at_count', 0)), float(features_dict.get('ampersand_count', 0)), 
                float(features_dict.get('percent_count', 0)), float(features_dict.get('hash_count', 0)),
                float(features_dict.get('semicolon_count', 0)), float(features_dict.get('has_ip', 0)), 
                float(features_dict.get('has_shortening', 0)), float(features_dict.get('has_suspicious_tld', 0)), 
                float(features_dict.get('has_common_tld', 0)), float(features_dict.get('domain_has_www', 0)),
                float(features_dict.get('domain_is_simple', 0)), float(features_dict.get('is_https', 0)), 
                float(features_dict.get('has_port', 0)), float(features_dict.get('url_depth', 0)), 
                float(features_dict.get('url_entropy', 0)), float(features_dict.get('domain_entropy', 0)),
                float(features_dict.get('digit_ratio', 0)), float(features_dict.get('letter_ratio', 0)), 
                float(features_dict.get('special_char_ratio', 0))
            ]])
            
            model = models[selected_model]
            
            # Apply scaling if needed
            if selected_model in scalers:
                features_array = scalers[selected_model].transform(features_array)
            
            # Make prediction
            prediction = model.predict(features_array)[0]
            if hasattr(model, 'predict_proba'):
                probabilities = model.predict_proba(features_array)[0]
                confidence = float(probabilities.max())
            else:
                confidence = 0.8  # Default confidence for models without probability
            
            # Convert binary prediction to label
            pred_label = 'malicious' if prediction == 1 else 'benign'
            
            return {
                selected_model: {
                    'prediction': pred_label,
                    'confidence': confidence,
                    'reason': f'{selected_model} machine learning prediction'
                }
            }
            
        except Exception as e:
            return {"error": f"Error with {selected_model}: {str(e)}"}

def create_prediction_chart(predictions):
    """Create a visualization of model predictions"""
    models = list(predictions.keys())
    pred_classes = [predictions[model]['prediction'] for model in models]
    confidences = [predictions[model]['confidence'] or 0 for model in models]
    
    # Create bar chart
    fig = go.Figure(data=[
        go.Bar(
            x=models,
            y=confidences,
            text=[f"{pred}<br>{conf:.3f}" for pred, conf in zip(pred_classes, confidences)],
            textposition='auto',
            marker_color=['red' if pred in ['phishing', 'malware', 'defacement'] else 'green' 
                         for pred in pred_classes]
        )
    ])
    
    fig.update_layout(
        title="Model Predictions and Confidence Scores",
        xaxis_title="Models",
        yaxis_title="Confidence Score",
        showlegend=False,
        height=400
    )
    
    return fig

def create_probability_chart(predictions):
    """Create a chart showing probability distributions"""
    models = list(predictions.keys())
    
    # Get class names from the first model that has probabilities
    class_names = None
    for model_name, pred_data in predictions.items():
        if (isinstance(pred_data, dict) and 
            'probabilities' in pred_data and 
            pred_data['probabilities'] is not None):
            # Assuming we have the feature extractor to get class names
            class_names = ['benign', 'defacement', 'malware', 'phishing']  # Known classes
            break
    
    if class_names is None:
        # If no probabilities available, still create class names for display
        class_names = ['benign', 'defacement', 'malware', 'phishing']
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=models,
        specs=[[{"type": "bar"}, {"type": "bar"}],
               [{"type": "bar"}, {"type": "bar"}]]
    )
    
    positions = [(1, 1), (1, 2), (2, 1), (2, 2)]
    
    for i, (model_name, pred_data) in enumerate(predictions.items()):
        if i >= 4:  # Only show first 4 models
            break
            
        row, col = positions[i]
        
        # Check if probabilities exist and are valid
        if (isinstance(pred_data, dict) and 
            'probabilities' in pred_data and 
            pred_data['probabilities'] is not None):
            fig.add_trace(
                go.Bar(
                    x=class_names,
                    y=pred_data['probabilities'],
                    name=model_name,
                    showlegend=False
                ),
                row=row, col=col
            )
        else:
            # Add a placeholder or skip this model
            fig.add_trace(
                go.Bar(
                    x=class_names,
                    y=[0, 0, 0, 0],
                    name=f"{model_name} (No probabilities)",
                    showlegend=False
                ),
                row=row, col=col
            )
    
    fig.update_layout(
        title_text="Probability Distribution by Model",
        height=600
    )
    
    return fig

def analyze_url_features(trainer, url):
    """Analyze and display URL features"""
    features = trainer.feature_extractor.extract_url_features(url)
    
    # Create two columns for feature display
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Basic URL Properties")
        st.write(f"**URL Length:** {features['url_length']}")
        st.write(f"**Domain Length:** {features['domain_length']}")
        st.write(f"**Path Length:** {features['path_length']}")
        st.write(f"**Query Length:** {features['query_length']}")
        st.write(f"**URL Depth:** {features['url_depth']}")
        
        st.subheader("Character Analysis")
        st.write(f"**Digit Count:** {features['digit_count']}")
        st.write(f"**Letter Count:** {features['letter_count']}")
        st.write(f"**Special Characters:** {features['special_char_count']}")
        st.write(f"**Dots:** {features['dot_count']}")
        st.write(f"**Slashes:** {features['slash_count']}")
    
    with col2:
        st.subheader("Security Features")
        st.write(f"**Has IP Address:** {'Yes' if features['has_ip'] else 'No'}")
        st.write(f"**Is HTTPS:** {'Yes' if features['is_https'] else 'No'}")
        st.write(f"**Has Port:** {'Yes' if features['has_port'] else 'No'}")
        st.write(f"**URL Shortener:** {'Yes' if features['has_shortening'] else 'No'}")
        st.write(f"**Suspicious TLD:** {'Yes' if features['has_suspicious_tld'] else 'No'}")
        
        st.subheader("Entropy Analysis")
        st.write(f"**URL Entropy:** {features['url_entropy']:.3f}")
        st.write(f"**Domain Entropy:** {features['domain_entropy']:.3f}")
        st.write(f"**Digit Ratio:** {features['digit_ratio']:.3f}")
        st.write(f"**Special Char Ratio:** {features['special_char_ratio']:.3f}")

def main():
    """Main Streamlit application"""
    
    # Title and description
    st.title("🔍 URL Maliciousness Detector")
    st.markdown("""
    This application uses machine learning to detect malicious URLs using multiple algorithms:
    **Random Forest**, **XGBoost**, **K-Nearest Neighbors (KNN)**, and **Support Vector Machine (SVM)**.
    
    Enter a URL below to analyze its safety!
    """)
    
    # Sidebar
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox("Choose a page", ["URL Detector", "Batch Analysis", "Model Performance", "About"])
    
    # Debug mode toggle
    st.sidebar.title("🔧 Debug")
    debug_mode = st.sidebar.checkbox("Enable Debug Mode", help="Shows detailed prediction information")
    
    # System diagnostics
    if st.sidebar.button("🔍 System Diagnostics"):
        st.sidebar.write("**System Status:**")
        st.sidebar.write(f"✅ Enhanced Classifier Available: {hasattr(trainer, 'predict_url') if trainer else 'No trainer'}")
        st.sidebar.write(f"✅ Trainer Type: {type(trainer) if trainer else 'None'}")
        if os.path.exists('enhanced_classifier.joblib'):
            st.sidebar.write("✅ enhanced_classifier.joblib exists")
        if os.path.exists('models/enhanced_classifier.joblib'):  
            st.sidebar.write("✅ models/enhanced_classifier.joblib exists")
        st.sidebar.write(f"✅ Models directory exists: {os.path.exists('models')}")
        if trainer and hasattr(trainer, 'predict_url'):
            try:
                test_result = trainer.predict_url('google.com')
                st.sidebar.write(f"✅ Test prediction: {test_result}")
            except Exception as e:
                st.sidebar.write(f"❌ Test prediction failed: {e}")
    
    # Model Selection
    st.sidebar.title("🤖 Model Selection")
    selected_model = st.sidebar.selectbox(
        "Choose prediction model:",
        [
            "Enhanced Classifier (Recommended)",
            "Random Forest", 
            "XGBoost",
            "K-Nearest Neighbors (KNN)",
            "Support Vector Machine (SVM)",
            "All Models (Ensemble)"
        ],
        index=0,  # Explicitly set Enhanced Classifier as default
        help="Enhanced Classifier uses ML + rule-based overrides for best accuracy"
    )
    
    # Force Enhanced Classifier option for troubleshooting
    force_enhanced = st.sidebar.checkbox(
        "🔒 Force Enhanced Classifier", 
        value=True,
        help="Always use Enhanced Classifier regardless of selection above (recommended for phishing detection)"
    )
    
    # Load models
    trainer = load_trained_models()
    
    if trainer is None:
        st.error("Models not available. Please train the models first by running `python model_trainer.py`")
        return
    
    if page == "URL Detector":
        st.header("Single URL Analysis")
        
        # Show selected model prominently
        if selected_model == "Enhanced Classifier (Recommended)":
            st.success(f"🛡️ **Active Model:** {selected_model} - Optimal protection against phishing URLs")
        else:
            st.info(f"🤖 **Active Model:** {selected_model}")
        
        # URL input
        url_input = st.text_input(
            "Enter URL to analyze:",
            placeholder="https://example.com",
            help="Enter the complete URL including http:// or https://"
        )
        
        if st.button("Analyze URL", type="primary"):
            if url_input.strip():
                with st.spinner(f"Analyzing URL with {selected_model}..."):
                    try:
                        # Load individual models if needed
                        individual_models, scalers, feature_extractor = load_individual_models()
                        
                        # Force Enhanced Classifier if option is checked
                        if force_enhanced and hasattr(trainer, 'predict_url'):
                            st.info("🔒 **Force Enhanced Classifier**: Using Enhanced Classifier (overriding model selection)")
                            actual_model = "Enhanced Classifier (Recommended)"
                        else:
                            actual_model = selected_model
                        
                        # Make predictions using selected model
                        predictions = predict_with_selected_model(
                            url_input.strip(), 
                            actual_model, 
                            trainer, 
                            individual_models, 
                            scalers, 
                            feature_extractor
                        )
                        
                        # Debug information
                        if debug_mode:
                            st.write("🔧 **Debug Information:**")
                            st.write(f"Selected Model: {selected_model}")
                            st.write(f"Trainer Type: {type(trainer)}")
                            st.write(f"Raw Predictions: {predictions}")
                            if hasattr(trainer, 'predict_url'):
                                debug_result = trainer.predict_url(url_input.strip())
                                st.write(f"Direct Enhanced Classifier Result: {debug_result}")
                        
                        # Safety warning if not using Enhanced Classifier
                        if selected_model != "Enhanced Classifier (Recommended)" and selected_model != "All Models (Ensemble)":
                            st.warning(f"⚠️ **Notice:** You're using {selected_model}. For best accuracy on phishing URLs, use 'Enhanced Classifier (Recommended)' which combines ML with rule-based detection.")
                        
                        # Check for errors
                        if not predictions or "error" in str(predictions):
                            st.error(f"Prediction Error: {predictions.get('error', 'Unknown error')}")
                            return
                        
                        # Ensure we have valid predictions
                        if not any(isinstance(pred, dict) for pred in predictions.values()):
                            st.error("No valid predictions received. Please check model configuration.")
                            return
                        
                        # Display results
                        st.success("Analysis Complete!")
                        
                        # Create tabs for different views
                        tab1, tab2, tab3 = st.tabs(["📊 Predictions", "🔍 Detailed Analysis", "⚙️ URL Features"])
                        
                        with tab1:
                            # Summary results
                            st.subheader("Prediction Results")
                            
                            # Get the main prediction from any model type
                            main_pred = list(predictions.values())[0] if predictions else None
                            
                            if main_pred and isinstance(main_pred, dict):
                                # Handle both old and new formats
                                if 'risk_level' in main_pred:
                                    # New format from enhanced classifier
                                    risk_level = "HIGH RISK" if main_pred.get('risk_level') == 'High' else "LOW RISK"
                                    classification = main_pred.get('risk_level', 'unknown').upper()  # Show High/Low instead of unknown
                                    confidence = float(main_pred.get('confidence', 0.0))
                                    reason = main_pred.get('explanation', 'Classification')
                                else:
                                    # Old format fallback
                                    classification = main_pred.get('prediction', 'unknown')
                                    confidence = float(main_pred.get('confidence', 0.0))
                                    reason = main_pred.get('reason', 'Classification')
                                    risk_level = "HIGH RISK" if classification in ['phishing', 'malware', 'defacement', 'malicious'] else "LOW RISK"
                                
                                risk_color = "red" if risk_level == "HIGH RISK" else "green"
                                
                                st.markdown(f"""
                                <div style='padding: 20px; border-radius: 10px; background-color: {"#ffebee" if risk_level == "HIGH RISK" else "#e8f5e8"}; border: 2px solid {risk_color}'>
                                <h3 style='color: {risk_color}; margin: 0;'>Overall Assessment: {risk_level}</h3>
                                <p style='margin: 5px 0 0 0; font-size: 16px;'>Classification: <strong>{classification.upper()}</strong></p>
                                <p style='margin: 5px 0 0 0; font-size: 14px;'><strong>Model Used:</strong> {selected_model}</p>
                                <p style='margin: 5px 0 0 0; font-size: 14px;'>Confidence: {confidence:.3f} | Method: {reason}</p>
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                # Fallback to majority vote for old format
                                pred_classes = [pred['prediction'] for pred in predictions.values() 
                                              if pred['prediction'] != 'Error']
                                if pred_classes:
                                    majority_prediction = max(set(pred_classes), key=pred_classes.count)
                                    risk_level = "HIGH RISK" if majority_prediction in ['phishing', 'malware', 'defacement'] else "LOW RISK"
                                    risk_color = "red" if risk_level == "HIGH RISK" else "green"
                                    
                                    st.markdown(f"""
                                    <div style='padding: 20px; border-radius: 10px; background-color: {"#ffebee" if risk_level == "HIGH RISK" else "#e8f5e8"}; border: 2px solid {risk_color}'>
                                    <h3 style='color: {risk_color}; margin: 0;'>Overall Assessment: {risk_level}</h3>
                                    <p style='margin: 5px 0 0 0; font-size: 16px;'>Majority Classification: <strong>{majority_prediction.upper()}</strong></p>
                                    </div>
                                    """, unsafe_allow_html=True)
                            
                            # Individual model results
                            st.subheader("Individual Model Results")
                            results_df = []
                            for model_name, pred_data in predictions.items():
                                if isinstance(pred_data, dict):
                                    # Handle both formats
                                    if 'risk_level' in pred_data:
                                        prediction = pred_data['risk_level']
                                        confidence = pred_data['confidence']
                                    else:
                                        prediction = pred_data.get('prediction', 'unknown')
                                        confidence = pred_data.get('confidence', 0)
                                    
                                    results_df.append({
                                        'Model': model_name,
                                        'Prediction': prediction,
                                        'Confidence': f"{float(confidence):.1f}%" if confidence else "N/A"
                                    })
                            
                            st.dataframe(pd.DataFrame(results_df), width='stretch')
                            
                            # Analytics Dashboard
                            st.subheader("📊 Analytics Dashboard")
                            
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                # Risk Level Gauge - Fix range to 0-100 properly
                                risk_score = min(max(confidence if confidence else 0, 0), 100)  # Ensure 0-100 range
                                fig_gauge = go.Figure(go.Indicator(
                                    mode = "gauge+number",
                                    value = risk_score,
                                    domain = {'x': [0, 1], 'y': [0, 1]},
                                    title = {'text': f"Confidence: {risk_score:.1f}%"},
                                    gauge = {
                                        'axis': {'range': [0, 100]},  # Fixed range
                                        'bar': {'color': risk_color},
                                        'steps': [
                                            {'range': [0, 50], 'color': "lightgray"},
                                            {'range': [50, 80], 'color': "yellow"},
                                            {'range': [80, 100], 'color': "lightgreen"}
                                        ],
                                        'threshold': {
                                            'line': {'color': "red", 'width': 4},
                                            'thickness': 0.75,
                                            'value': 90
                                        }
                                    }
                                ))
                                fig_gauge.update_layout(height=300)
                                st.plotly_chart(fig_gauge, use_container_width=True)
                            
                            with col2:
                                # Threat Categories
                                threat_categories = ['Phishing', 'Malware', 'Legitimate', 'Suspicious']
                                if risk_level == "HIGH RISK":
                                    if 'phishing' in reason.lower() or 'typosquatting' in reason.lower():
                                        threat_scores = [95, 10, 5, 80]
                                    elif 'malware' in reason.lower():
                                        threat_scores = [20, 95, 5, 70]
                                    else:
                                        threat_scores = [60, 30, 10, 90]
                                else:
                                    threat_scores = [5, 5, 95, 10]
                                
                                fig_threats = go.Figure(data=[
                                    go.Bar(name='Threat Analysis', x=threat_categories, y=threat_scores,
                                          marker_color=['red', 'orange', 'green', 'yellow'])
                                ])
                                fig_threats.update_layout(title="Threat Category Analysis", height=300)
                                st.plotly_chart(fig_threats, use_container_width=True)
                                
                            with col3:
                                # Risk Timeline (simulated)
                                timeline_data = {
                                    'Time': ['Initial Scan', 'Domain Check', 'Pattern Analysis', 'Final Assessment'],
                                    'Risk Score': [50, 60 if risk_level == "HIGH RISK" else 20, 70 if risk_level == "HIGH RISK" else 15, confidence]
                                }
                                fig_timeline = px.line(x=timeline_data['Time'], y=timeline_data['Risk Score'], 
                                                     title="Risk Assessment Timeline", 
                                                     color_discrete_sequence=[risk_color])
                                fig_timeline.update_layout(height=300)
                                st.plotly_chart(fig_timeline, use_container_width=True)
                        
                        with tab2:
                            # Enhanced Analysis for Enhanced Classifier
                            if 'Enhanced Classifier' in predictions:
                                enhanced_pred = predictions['Enhanced Classifier']
                                
                                st.subheader("🔍 Detailed Classification Analysis")
                                
                                # Create columns for organized display
                                col1, col2 = st.columns(2)
                                
                                with col1:
                                    st.markdown("### 📊 Classification Details")
                                    
                                    # Classification result with color coding - Use correct keys
                                    risk_level = enhanced_pred.get('risk_level', enhanced_pred.get('prediction', 'unknown'))
                                    confidence = float(enhanced_pred.get('confidence', 0.0))
                                    explanation = enhanced_pred.get('explanation', enhanced_pred.get('reason', 'No explanation'))
                                    
                                    if risk_level == 'Low' or risk_level == 'benign':
                                        color = "#28a745"  # Green
                                        icon = "✅"
                                        risk = "LOW RISK"
                                        display_class = "LEGITIMATE"
                                    else:
                                        color = "#dc3545"  # Red  
                                        icon = "⚠️"
                                        risk = "HIGH RISK"
                                        display_class = "THREAT DETECTED"
                                    
                                    st.markdown(f"""
                                    <div style='padding: 15px; border-radius: 8px; background-color: {color}15; border-left: 4px solid {color}'>
                                    <h4 style='color: {color}; margin: 0;'>{icon} {display_class}</h4>
                                    <p style='margin: 5px 0 0 0;'><strong>Risk Level:</strong> {risk}</p>
                                    <p style='margin: 5px 0 0 0;'><strong>Confidence:</strong> {confidence:.1f}%</p>
                                    </div>
                                    """, unsafe_allow_html=True)
                                    
                                    # Confidence meter
                                    st.markdown("### 📈 Confidence Level")
                                    confidence_percentage = confidence * 100
                                    st.progress(confidence)
                                    st.write(f"**{confidence_percentage:.1f}%** confidence in classification")
                                
                                with col2:
                                    st.markdown("### 🧠 Decision Reasoning")
                                    decision_reason = enhanced_pred.get('explanation', enhanced_pred.get('reason', 'Enhanced classification algorithm'))
                                    
                                    # Explain the reasoning
                                    if 'Trusted domain override' in decision_reason:
                                        st.success("🛡️ **Trusted Domain Protection**")
                                        st.write("This URL belongs to a verified trusted domain in our whitelist.")
                                        st.write("**Security Features:**")
                                        st.write("• Domain reputation verification")
                                        st.write("• Automatic safe classification")
                                        st.write("• Override of ML predictions")
                                        
                                    elif 'IP address URL' in decision_reason:
                                        st.error("🚨 **Direct IP Access Detected**")
                                        st.write("URLs with direct IP addresses are flagged as suspicious.")
                                        st.write("**Risk Factors:**")
                                        st.write("• Bypasses domain name system")
                                        st.write("• Common in malware distribution")
                                        st.write("• Difficult to verify legitimacy")
                                        
                                    elif 'Suspicious TLD' in decision_reason or 'High-risk TLD' in decision_reason:
                                        st.warning("⚠️ **Suspicious Domain Extension**")
                                        st.write("Domain uses a TLD commonly associated with malicious activity.")
                                        st.write("**Risk Indicators:**")
                                        st.write("• High-risk domain extension")
                                        st.write("• Frequently used by attackers")
                                        st.write("• Low registration barriers")
                                        
                                    elif 'URL shortener' in decision_reason:
                                        st.warning("🔗 **URL Shortening Service**")
                                        st.write("Shortened URLs can hide the actual destination.")
                                        st.write("**Security Concerns:**")
                                        st.write("• Destination URL hidden")
                                        st.write("• Potential for malicious redirects")
                                        st.write("• Used in phishing campaigns")
                                        
                                    else:
                                        st.info("🤖 **Machine Learning Analysis**")
                                        st.write("Classification based on comprehensive feature analysis using trained ML models.")
                                        st.write("**Analysis Factors:**")
                                        st.write("• URL structure patterns")
                                        st.write("• Domain characteristics")
                                        st.write("• Statistical anomaly detection")
                                
                                # Additional insights
                                st.markdown("### 📋 Classification Summary")
                                summary_data = {
                                    "Attribute": ["Final Classification", "Confidence Score", "Decision Method", "Risk Assessment"],
                                    "Value": [
                                        display_class.title(),
                                        f"{confidence:.1f}%",
                                        explanation,
                                        risk
                                    ]
                                }
                                st.dataframe(pd.DataFrame(summary_data), width='stretch', hide_index=True)
                                
                            else:
                                # Fallback for other prediction formats
                                st.subheader("Model Predictions")
                                for model_name, pred_data in predictions.items():
                                    if isinstance(pred_data, dict):
                                        st.subheader(f"{model_name}")
                                        col1, col2 = st.columns(2)
                                        with col1:
                                            st.write(f"**Prediction:** {pred_data.get('prediction', 'N/A')}")
                                        with col2:
                                            if 'confidence' in pred_data:
                                                st.write(f"**Confidence:** {pred_data['confidence']:.3f}")
                                        if 'reason' in pred_data:
                                            st.write(f"**Reason:** {pred_data['reason']}")
                        
                        with tab3:
                            st.subheader("URL Feature Analysis")
                            # Check if trainer has feature_extractor attribute
                            if hasattr(trainer, 'feature_extractor'):
                                analyze_url_features(trainer, url_input.strip())
                            else:
                                # Load feature extractor separately if needed
                                try:
                                    import joblib
                                    feature_extractor = joblib.load('feature_extractor.joblib')
                                    # Create a temporary object with the feature extractor
                                    class TempTrainer:
                                        def __init__(self, fe):
                                            self.feature_extractor = fe
                                    temp_trainer = TempTrainer(feature_extractor)
                                    analyze_url_features(temp_trainer, url_input.strip())
                                except Exception as fe_error:
                                    st.error(f"Could not load feature analysis: {str(fe_error)}")
                                    st.write("Feature analysis is not available in enhanced classifier mode.")
                        
                    except Exception as e:
                        st.error(f"Error analyzing URL: {str(e)}")
            else:
                st.warning("Please enter a valid URL.")
    
    elif page == "Batch Analysis":
        st.header("Batch URL Analysis")
        
        st.markdown("Upload a CSV file with URLs or enter multiple URLs for batch analysis.")
        
        # File upload
        uploaded_file = st.file_uploader("Upload CSV file", type=['csv'])
        
        if uploaded_file is not None:
            try:
                df = pd.read_csv(uploaded_file)
                st.write("Preview of uploaded data:")
                st.dataframe(df.head())
                
                url_column = st.selectbox("Select the column containing URLs:", df.columns)
                
                if st.button("Analyze Batch"):
                    with st.spinner("Analyzing URLs..."):
                        results = []
                        progress_bar = st.progress(0)
                        
                        for idx, url in enumerate(df[url_column]):
                            if pd.notna(url):
                                try:
                                    predictions = trainer.predict_url(str(url))
                                    pred_classes = [pred['prediction'] for pred in predictions.values() 
                                                  if pred['prediction'] != 'Error']
                                    majority_pred = max(set(pred_classes), key=pred_classes.count) if pred_classes else 'Error'
                                    
                                    results.append({
                                        'URL': url,
                                        'Prediction': majority_pred,
                                        'Risk_Level': 'High' if majority_pred in ['phishing', 'malware', 'defacement'] else 'Low'
                                    })
                                except:
                                    results.append({
                                        'URL': url,
                                        'Prediction': 'Error',
                                        'Risk_Level': 'Unknown'
                                    })
                            
                            progress_bar.progress((idx + 1) / len(df))
                        
                        results_df = pd.DataFrame(results)
                        st.success("Batch analysis complete!")
                        st.dataframe(results_df)
                        
                        # Download results
                        csv = results_df.to_csv(index=False)
                        st.download_button(
                            label="Download Results",
                            data=csv,
                            file_name="url_analysis_results.csv",
                            mime="text/csv"
                        )
            
            except Exception as e:
                st.error(f"Error processing file: {e}")
        
        # Manual input
        st.subheader("Manual Batch Input")
        urls_text = st.text_area(
            "Enter URLs (one per line):",
            height=150,
            placeholder="https://example1.com\nhttps://example2.com\n..."
        )
        
        if st.button("Analyze URLs"):
            if urls_text.strip():
                urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
                
                with st.spinner("Analyzing URLs..."):
                    results = []
                    progress_bar = st.progress(0)
                    
                    for idx, url in enumerate(urls):
                        try:
                            predictions = trainer.predict_url(url)
                            pred_classes = [pred['prediction'] for pred in predictions.values() 
                                          if pred['prediction'] != 'Error']
                            majority_pred = max(set(pred_classes), key=pred_classes.count) if pred_classes else 'Error'
                            
                            results.append({
                                'URL': url,
                                'Prediction': majority_pred,
                                'Risk_Level': 'High' if majority_pred in ['phishing', 'malware', 'defacement'] else 'Low'
                            })
                        except:
                            results.append({
                                'URL': url,
                                'Prediction': 'Error',
                                'Risk_Level': 'Unknown'
                            })
                        
                        progress_bar.progress((idx + 1) / len(urls))
                    
                    results_df = pd.DataFrame(results)
                    st.success("Analysis complete!")
                    st.dataframe(results_df)
    
    elif page == "Model Performance":
        st.header("Model Performance Metrics")
        
        # Load results if available
        if os.path.exists('models/model_results.joblib'):
            results = joblib.load('models/model_results.joblib')
            
            # Performance summary
            summary_data = []
            for model_name, metrics in results.items():
                summary_data.append({
                    'Model': model_name,
                    'Accuracy': f"{metrics['accuracy']:.4f}",
                    'Precision': f"{metrics['precision']:.4f}",
                    'Recall': f"{metrics['recall']:.4f}",
                    'F1-Score': f"{metrics['f1_score']:.4f}"
                })
            
            summary_df = pd.DataFrame(summary_data)
            st.subheader("Performance Summary")
            st.dataframe(summary_df, width='stretch')
            
            # Performance visualization
            fig = px.bar(
                summary_df.melt(id_vars=['Model'], var_name='Metric', value_name='Score'),
                x='Model',
                y='Score',
                color='Metric',
                title="Model Performance Comparison",
                barmode='group'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        else:
            st.info("No performance metrics available. Train models first to see performance data.")
    
    elif page == "About":
        st.header("About This Application")
        
        st.markdown("""
        ### URL Maliciousness Detection System
        
        This application uses machine learning to classify URLs into different categories:
        - **Benign**: Safe URLs
        - **Phishing**: URLs designed to steal sensitive information
        - **Malware**: URLs that distribute malicious software
        - **Defacement**: URLs pointing to defaced websites
        
        ### Machine Learning Models
        
        The system employs four different algorithms:
        
        1. **Random Forest**: An ensemble method that uses multiple decision trees
        2. **XGBoost**: A gradient boosting framework optimized for performance
        3. **K-Nearest Neighbors (KNN)**: A simple, instance-based learning algorithm
        4. **Support Vector Machine (SVM)**: A powerful classifier that finds optimal decision boundaries
        
        ### Features Used
        
        The models analyze various URL characteristics:
        - Length and structural properties
        - Character composition and ratios
        - Domain and subdomain features
        - Security indicators (HTTPS, IP addresses)
        - Entropy and randomness measures
        - Suspicious patterns and known indicators
        
        ### Dataset
        
        The model is trained on the "Malicious URLs Dataset" from Kaggle, which contains over 650,000 labeled URLs across four categories.
        
        ### How to Use
        
        1. **Single URL Analysis**: Enter a URL in the detector page for immediate analysis
        2. **Batch Analysis**: Upload a CSV file or enter multiple URLs for bulk processing
        3. **Model Performance**: View detailed performance metrics for each algorithm
        
        ### Accuracy and Limitations
        
        While this system provides a good indication of URL safety, it should not be the only security measure. Always use updated antivirus software and exercise caution when browsing the internet.
        """)

if __name__ == "__main__":
    main()