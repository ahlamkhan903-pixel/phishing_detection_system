**Phishing Website Detection System**

A Machine Learning web application that detects whether a website is phishing or legitimate.
The system automatically visits a website, extracts 30 security features, and classifies it using a trained Random Forest model.

**What This Project Does?**

Accepts any website URL as input

Automatically extracts 30 security features from the site

Classifies it as Phishing or Legitimate using Machine Learning

Shows a confidence score and risk level (Safe / Suspicious / Dangerous)

Provides a 4-category security breakdown explaining what was checked


**Project Structure**

phishing-detection-system/
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
    ├── model_metadata.json     
    ├── model_comparison.png    
    └── confusion_matrices.png  

**Dataset**

Kaggle — Phishing Website Dataset

Dataset Total websites 11,054

Features 30 (encoded as -1, 0, or 1)

Target column class (-1 = Phishing, 1 = Legitimate)

Missing values None

Class balance 55.7% Legitimate / 44.3% Phishing

**Machine Learning Models**

Two models were trained and compared. The best one is selected automatically.
Metric Logistic Regression and Random Forest 

**Accuracy**: 93.89% vs 97.42%

**Precision**: 93.69% vs 98.02%

**Recall**: 92.44% vs 96.12%

**F1-Score**: 93.06% vs 97.06%

**ROC-AUC**: 0.9824 vs 0.9945

**Random Forest** was selected as the final model based on highest ROC-AUC score.

**Risk Level Classification**

Phishing Probability Risk Level  

0% to 40%  **Safe** 

40% to 70%  **Suspicious**

70% to 100% **Dangerous**


**Security Feature Categories**

The 30 features are grouped into 4 categories:
**1. URL Structure — Checks the web address itself**

IP in URL, 
URL length, 

shortening service,

@ symbol, 

double-slash redirect,

hyphen in domain, 

sub-domains,

https word in domain

**2. Security and Domain — Checks domain trustworthiness**
   
HTTPS certificate, 

domain age, 

registration length, 

favicon source, 

non-standard port, 

URL mismatch,

DNS record

**3. Page Content and Behaviour — Checks what the page does**
External resources percentage,

anchor links, script tags, form submission target,

mailto in form, 

number of redirects, 

status bar change,

right-click disabled, 

pop-up windows, 

hidden iframes

**4. Reputation and Trust — Checks if the site is known**
Web traffic rank,

PageRank score, 

Google indexing, 

backlinks,

phishing databases


**Setup Instructions**
**Requirements**

Python 3.9 or higher
Internet connection (needed for scanning live URLs)


Step 1 — Download the project
Download all files and place them in one folder on your computer.

Step 2 — Install dependencies
Open a terminal in the project folder and run:
pip install -r requirements.txt

Step 3 — Train the models
Run the training script:

python train_model.py

This will train both models, compare them, and save the best one.

Expected output at the end:
Training Complete!
Best Model  : Random Forest
Accuracy    : 97.42%

Step 4 — Launch the web application
streamlit run app.py
Open your browser at: http://localhost:8501

**How to Use**

Paste any website URL into the input box

Click Scan URL

Wait 5 to 15 seconds while the site is visited and analyzed

View the results — verdict, confidence score, risk level, and security breakdown


**Academic Info**

Project: BSCS 7th Semester

Topic: Phishing Website Detection using Machine Learning

Models Used: Logistic Regression, Random Forest

Framework: Streamlit

Dataset: Kaggle — Phishing Website Dataset (11,054 websites)
