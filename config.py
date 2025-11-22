# Production configuration for Streamlit
import os

# Set page config for production
PRODUCTION_CONFIG = {
    'page_title': 'URL Maliciousness Detector',
    'page_icon': '🔍',
    'layout': 'wide',
    'initial_sidebar_state': 'expanded'
}

# Production optimizations
CACHE_CONFIG = {
    'allow_output_mutation': True,
    'show_spinner': False,
    'persist': 'disk'
}

# Environment variables
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'
MODEL_CACHE_DIR = os.getenv('MODEL_CACHE_DIR', './models')

# Production settings
if ENVIRONMENT == 'production':
    DEBUG_MODE = False
    # Optimize for production
    import streamlit as st
    st.set_option('deprecation.showPyplotGlobalUse', False)
    st.set_option('deprecation.showfileUploaderEncoding', False)