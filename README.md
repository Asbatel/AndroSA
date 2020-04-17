# Welcome to AndroSA

AndroSA is a framework meant to apply static analysis and detection of Android malware based on a feature set containing the Manifest attributes and API calls.

# Requirements

AndroSA depends on the following tools:

   - Androguard: It is used for statically analyzing the target APK and extracting its contextual and structural data (https://github.com/androguard/androguard)
   - scikit-learn: Machine learning library for Python
   
# Installation

AndroSa can be installed as follows:

   - Download or clone the repo (git clone https://github.com/Asbatel/AndroSA.git)
   - Navigate to the main directory (cd androsa)
   - Install the required tools (Androguard + Scikit-learn)

# Usage

To test an APK, simply run the following command: `python check_apk.py <apk_path>`




