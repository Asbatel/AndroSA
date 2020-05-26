# Welcome to AndroSA

AndroSA is a framework meant to apply static analysis and detection of Android malware based on a feature set containing the Manifest attributes and API calls.

# Evaluation

Our framework has been evaluated against 30,000 apks from both <a href="https://www.sec.cs.tu-bs.de/~danarp/drebin/">Drebin</a> and <a href="http://amd.arguslab.org/">AMD</a>. Our approach yields an accuracy of 91.4%, which is nearly comparable to state-of-the-art techniques.

# Requirements

AndroSA depends on the following tools:

   - **Androguard**: It is used for statically analyzing the target APK and extracting its contextual and structural data. (https://github.com/androguard/androguard)
   - **scikit-learn**: Machine learning library for Python.
   
# Installation and Usage

To test an APK:

   - Download or clone the repo (git clone https://github.com/Asbatel/AndroSA.git)
   - Install the required tools (Androguard + scikit-learn)  
   - Navigate to the main directory `cd androsa/`
   - Run the following command: `python check_apk.py <apk_path>`







