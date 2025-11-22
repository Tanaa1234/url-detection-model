"""
Data downloader and explorer for malicious URLs dataset
"""

import kagglehub
import pandas as pd
import os
import numpy as np

def download_dataset():
    """Download the malicious URLs dataset from Kaggle"""
    print("Downloading malicious URLs dataset...")
    path = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
    print(f"Path to dataset files: {path}")
    return path

def explore_dataset(dataset_path):
    """Explore the structure of the downloaded dataset"""
    print(f"\nExploring dataset at: {dataset_path}")
    
    # List all files in the dataset directory
    files = os.listdir(dataset_path)
    print(f"Files in dataset: {files}")
    
    # Try to find CSV files
    csv_files = [f for f in files if f.endswith('.csv')]
    print(f"CSV files found: {csv_files}")
    
    if csv_files:
        # Load the first CSV file
        csv_path = os.path.join(dataset_path, csv_files[0])
        df = pd.read_csv(csv_path)
        
        print(f"\nDataset shape: {df.shape}")
        print(f"Columns: {df.columns.tolist()}")
        print(f"\nFirst few rows:")
        print(df.head())
        print(f"\nData types:")
        print(df.dtypes)
        print(f"\nMissing values:")
        print(df.isnull().sum())
        
        # Check target distribution
        if 'type' in df.columns:
            print(f"\nTarget distribution:")
            print(df['type'].value_counts())
        elif 'label' in df.columns:
            print(f"\nTarget distribution:")
            print(df['label'].value_counts())
        
        return df, csv_path
    
    return None, None

if __name__ == "__main__":
    # Download dataset
    dataset_path = download_dataset()
    
    # Explore dataset
    df, csv_path = explore_dataset(dataset_path)
    
    if df is not None:
        print(f"\nDataset successfully loaded from: {csv_path}")
        print("Ready for preprocessing and model training!")
    else:
        print("No CSV files found in the dataset!")