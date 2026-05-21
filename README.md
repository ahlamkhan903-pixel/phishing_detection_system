🛡️ Phishing Website Detection System

A Machine Learning web application that detects whether a website is Phishing or Legitimate — with confidence score, risk level classification, and a detailed 4-category security breakdown.


📌 Project Overview
This project was developed as a BSCS 7th Semester Project to demonstrate the application of Machine Learning in cybersecurity. The system automatically visits a website, extracts 30 security features, and classifies it using a trained Random Forest model — achieving 97.4% accuracy.


✨ Features

🔗 Automatic URL scanning — just paste a URL and click Scan
🤖 Two ML models compared — Logistic Regression vs Random Forest
📊 Confidence score — percentage certainty of the prediction
🚦 Risk level classification — Safe / Suspicious / Dangerous
🔍 4-category security breakdown — URL Structure, Security & Domain, Page Content, Reputation & Trust
🚩 Phishing indicator cards — shows exactly what was detected and why
📄 Downloadable HTML report — full analysis you can open in any browser


🗂️ Project Structure
phishing-detection/
│
├── app.py
├── train_model.py         
├── config.py               
├── model_utils.py          
├── url_features.py         
├── requirements.txt       
├── phishing.csv           
│
└── models/                 
    ├── best_model.pkl         
    ├── scaler.pkl             
    ├── model_metadata.json     
    ├── model_comparison.png    
    └── confusion_matrices.png  

🧠 Machine Learning Details
Dataset
PropertyValueSourceKaggle — UCI Phishing Website DatasetTotal websites11,054Features30 (pre-extracted, encoded as -1 / 0 / 1)Targetclass (-1 = Phishing, 1 = Legitimate)Missing values0Class balance55.7% Legitimate / 44.3% Phishing
Models Compared
MetricLogistic RegressionRandom ForestAccuracy93.89%97.42% ✅Precision93.69%98.02%Recall92.44%96.12%F1-Score93.06%97.06%ROC-AUC0.98240.9945CV Score92.37% ± 0.82%97.05% ± 0.38%
Random Forest was selected automatically based on highest ROC-AUC score.
Risk Level Thresholds
Phishing ProbabilityRisk Level0% – 40%✅ Safe40% – 70%⚠️ Suspicious70% – 100%🚨 Dangerous
Feature Categories
CategoryFeatures🔗 URL StructureIP in URL, URL length, shortening service, @ symbol, redirects, hyphens, sub-domains, https in domain🔒 Security & DomainHTTPS/SSL, domain age, registration length, favicon source, DNS record, port, URL mismatch📄 Page Content & BehaviourExternal resources, anchor links, form targets, iframes, pop-ups, right-click disabled, redirects📈 Reputation & TrustWeb traffic rank, PageRank, Google indexing, backlinks, phishing databases

⚙️ Setup & Installation
Requirements

Python 3.9 or higher
Internet connection (for scanning live URLs)

Step 1 — Clone the repository
bashgit clone https://github.com/YOUR_USERNAME/phishing-detection-system.git
cd phishing-detection-system
Step 2 — Create a virtual environment
bash# Windows
python -m venv venv
venv\Scripts\activate

Now run:  streamlit run app.py
Step 5 — Launch the web application
bashstreamlit run app.py
Open your browser at: http://localhost:8501

🚀 How to Use

Paste any website URL into the input box
Click Scan URL
Wait 5–15 seconds while the site is visited and analyzed
View the results:

✅ / ⚠️ / 🚨 Classification verdict
Confidence percentage
Risk level badge
Probability breakdown bars
4-category security score cards
Phishing indicator cards (what was detected and why)


Download the HTML report if needed


📦 Dependencies
scikit-learn>=1.3.0
numpy>=1.24.0
pandas>=2.0.0
joblib>=1.3.0
streamlit>=1.32.0
matplotlib>=3.7.0
seaborn>=0.12.0
requests>=2.31.0
beautifulsoup4>=4.12.0
python-whois>=0.8.0
urllib3>=2.0.0

🔧 File Descriptions
FilePurposeapp.pyStreamlit web UI — the application users interact withtrain_model.pyFull ML pipeline: load data → preprocess → split → scale → train → evaluate → saveconfig.pyCentral configuration: all paths, thresholds, and feature definitionsmodel_utils.pyShared functions: save/load model, predict, classify riskurl_features.pyVisits a live URL and extracts all 30 features automatically


📄 License
This project is for academic purposes only.
