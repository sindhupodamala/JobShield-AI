🛡️ JobShield AI – AI-Powered Job Scam Detection System

📌 About the Project

JobShield AI is an AI-powered job advertisement scam detection system designed to identify potentially fraudulent job postings.

It uses Machine Learning, Optical Character Recognition (OCR), and risk analysis to examine job advertisements and help job seekers recognize suspicious recruitment offers.

🎯 Objectives

- Detect potentially fake job advertisements.
- Identify suspicious recruitment information.
- Analyze job advertisement images using OCR.
- Calculate risk scores and threat levels.
- Help job seekers avoid recruitment scams.

✨ Features

- AI Job Scanner: Predicts whether a job advertisement is potentially Fake or Genuine.
- Image Upload & OCR: Extracts text from uploaded job advertisement images.
- Risk Score Analysis: Displays risk scores and threat levels.
- Evidence Analysis: Highlights suspicious words and warning signs.
- Company Trust Check: Performs basic checks on company and recruiter information.
- Dashboard: Displays job scanning statistics and analytics.
- Scan History: Stores previous scan results.
- Scam Pattern Network: Visualizes repeated recruiter emails and website domains.
- Scan Report: Allows users to download scan reports.

🛠️ Technologies Used

- Python
- Flask
- Machine Learning
- Scikit-learn
- TF-IDF
- Logistic Regression
- HTML
- CSS
- JavaScript
- SQLite
- Tesseract OCR
- Chart.js

📂 Project Structure

JobShield-AI/
│
├── dataset/
├── ml_models/
├── statics/
├── templates/
├── uploads/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE

⚙️ Installation and Setup

1. Clone the repository

git clone https://github.com/YOUR-USERNAME/JobShield-AI.git

2. Open the project folder

cd JobShield-AI

3. Create a virtual environment

python -m venv .venv

4. Activate the environment

Windows:

.venv\Scripts\activate

5. Install dependencies

pip install -r requirements.txt

6. Install Tesseract OCR

Install Tesseract OCR separately and configure its executable path in the application if required.

7. Run the application

python app.py

8. Open in your browser

http://127.0.0.1:5000

🔍 How It Works

1. User enters a job advertisement or uploads an image.
2. OCR extracts text from the uploaded image when applicable.
3. The Machine Learning model analyzes the advertisement.
4. Risk analysis checks for suspicious indicators.
5. The application displays the prediction, risk score, and warnings.
6. Scan results can be viewed in the dashboard and scan history.

⚠️ Disclaimer

JobShield AI is an educational project designed to help identify potentially fraudulent job advertisements. Its predictions are not guaranteed. Users should independently verify employers and job offers before sharing personal information or making payments.

🚀 Future Enhancements

- Real-time company verification.
- Improved scam detection accuracy.
- More recruitment scam datasets.
- Advanced AI-based fraud analysis.
- Enhanced security and reporting features.

👩‍💻 Author

Developed as an Artificial Intelligence and Machine Learning project.

Project Name: JobShield AI

Purpose: AI-powered Job Scam Detection

---

⭐ If you find this project interesting, consider giving the repository a star!
