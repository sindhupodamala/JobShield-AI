
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from PIL import Image
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import pytesseract
import sqlite3
import uuid
import joblib
import re

app = Flask(__name__)

# ---------------- PROJECT PATHS ----------------

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "ml_model" / "job_model.pkl"
DATABASE_PATH = BASE_DIR / "jobshield.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"

UPLOAD_FOLDER.mkdir(exist_ok=True)

model = joblib.load(MODEL_PATH)

print("JobShield AI real-data model loaded successfully!")

pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


# ---------------- DATABASE ----------------

def get_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    with get_db() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_text TEXT NOT NULL,
                prediction TEXT NOT NULL,
                label INTEGER NOT NULL,
                confidence REAL NOT NULL,
                risk_level TEXT NOT NULL,
                reasons TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                recruiter_email TEXT,
                website_domain TEXT
            )
        """)

        existing_columns = [
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scan_history)"
            ).fetchall()
        ]

        if "recruiter_email" not in existing_columns:
            connection.execute("""
                ALTER TABLE scan_history
                ADD COLUMN recruiter_email TEXT
            """)

        if "website_domain" not in existing_columns:
            connection.execute("""
                ALTER TABLE scan_history
                ADD COLUMN website_domain TEXT
            """)


create_database()


# ---------------- FILE HELPERS ----------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ---------------- COMPANY DETAIL EXTRACTION ----------------

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "rediffmail.com"
}


def extract_company_details(
    company_name="",
    website="",
    recruiter_email="",
    job_text=""
):
    if not company_name:
        match = re.search(
            r"(?im)^\s*(?:company|organization|employer)\s*[:\-]\s*(.+?)\s*$",
            job_text
        )
        if match:
            company_name = match.group(1).strip()

    if not website:
        match = re.search(
            r"(?im)^\s*(?:company website|official website|website)\s*[:\-]\s*(https?://\S+|www\.\S+)\s*$",
            job_text
        )
        if match:
            website = match.group(1).rstrip(".,;")

    if not website:
        match = re.search(
            r"(?:https?://|www\.)[^\s,<>]+",
            job_text,
            re.IGNORECASE
        )
        if match:
            website = match.group(0).rstrip(".,;")

    if not recruiter_email:
        match = re.search(
            r"(?im)^\s*(?:recruiter email|contact email|email)\s*[:\-]\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            job_text
        )
        if match:
            recruiter_email = match.group(1)

    if not recruiter_email:
        match = re.search(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            job_text
        )
        if match:
            recruiter_email = match.group(0)

    return (
        company_name.strip(),
        website.strip(),
        recruiter_email.strip().lower()
    )


def extract_website_domain(website):
    if not website:
        return ""

    try:
        parsed = urlparse(
            website if "://" in website else "https://" + website
        )

        domain = (parsed.hostname or "").lower()

        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except Exception:
        return ""


# ---------------- SCAM EVIDENCE ENGINE ----------------

WARNING_PATTERNS = [
    {
        "phrase": r"registration fee",
        "category": "Payment Request",
        "severity": "High",
        "explanation": "The advertisement mentions a registration fee."
    },
    {
        "phrase": r"processing fee",
        "category": "Payment Request",
        "severity": "High",
        "explanation": "The advertisement mentions a processing fee."
    },
    {
        "phrase": r"security deposit",
        "category": "Payment Request",
        "severity": "High",
        "explanation": "The advertisement asks for a security deposit."
    },
    {
        "phrase": r"pay now|pay immediately",
        "category": "Payment Request",
        "severity": "High",
        "explanation": "The advertisement pressures applicants to make payment."
    },
    {
        "phrase": r"bank details|bank account details",
        "category": "Sensitive Information",
        "severity": "High",
        "explanation": "The advertisement mentions sensitive banking information."
    },
    {
        "phrase": r"\botp\b|one.time password",
        "category": "Sensitive Information",
        "severity": "High",
        "explanation": "The advertisement mentions requesting an OTP."
    },
    {
        "phrase": r"without interview|no interview required",
        "category": "Recruitment Process",
        "severity": "Medium",
        "explanation": "The advertisement promises employment without an interview."
    },
    {
        "phrase": r"guaranteed job|100% job guarantee",
        "category": "Unrealistic Promise",
        "severity": "Medium",
        "explanation": "The advertisement makes a guaranteed employment promise."
    },
    {
        "phrase": r"limited vacancies.*pay|pay.*limited vacancies",
        "category": "Pressure Tactics",
        "severity": "Medium",
        "explanation": "The advertisement combines payment with urgency."
    },
    {
        "phrase": r"whatsapp.*registration fee|registration fee.*whatsapp",
        "category": "Recruitment Fraud",
        "severity": "High",
        "explanation": "The advertisement combines WhatsApp recruitment with a fee request."
    }
]


def analyze_evidence(text):
    evidence = []
    text_lower = text.lower()

    # Phrases that indicate the employer does not request payment
    safe_phrases = [
        r"no\s+registration\s+fee",
        r"no\s+application\s+fee",
        r"no\s+payment\s+required",
        r"never\s+ask\s+for\s+payment",
        r"do\s+not\s+pay",
        r"does\s+not\s+require\s+payment",
        r"without\s+any\s+fee",
        r"free\s+to\s+apply",
        r"no\s+processing\s+fee"
    ]

    additional_patterns = [
        {
            "phrase": r"selected\s+without\s+(?:an?\s+)?interview",
            "category": "Suspicious Recruitment",
            "severity": "Medium",
            "explanation": "The candidate is reportedly selected without an interview."
        },
        {
            "phrase": r"guaranteed\s+(?:job|salary|placement|employment)",
            "category": "Unrealistic Promise",
            "severity": "Medium",
            "explanation": "The advertisement makes a guaranteed job or salary promise."
        },
        {
            "phrase": r"limited\s+vacancies|apply\s+immediately|act\s+now|urgent\s+payment",
            "category": "Urgency Pressure",
            "severity": "Medium",
            "explanation": "Urgent language may pressure candidates into making quick decisions."
        },
        {
            "phrase": r"salary\s+of\s+₹?\s*\d[\d,]*\s*(?:per\s+month|monthly)",
            "category": "Salary Claim",
            "severity": "Low",
            "explanation": "A specific salary claim was found. Verify it against the official job listing."
        }
    ]

    patterns = list(WARNING_PATTERNS) + additional_patterns
    checked = set()

    for item in patterns:

        for match in re.finditer(item["phrase"], text_lower):

            sentence_start = max(
                text_lower.rfind(".", 0, match.start()),
                text_lower.rfind("\n", 0, match.start()),
                text_lower.rfind("!", 0, match.start()),
                text_lower.rfind("?", 0, match.start())
            ) + 1

            sentence_end = len(text_lower)

            for separator in [".", "\n", "!", "?"]:
                position = text_lower.find(separator, match.end())

                if position != -1:
                    sentence_end = min(sentence_end, position)

            sentence = text_lower[sentence_start:sentence_end]

            # Ignore payment warnings when the sentence explicitly
            # says that no payment or fee is required.
            if any(
                re.search(pattern, sentence)
                for pattern in safe_phrases
            ):
                if item["category"] in [
                    "Payment Request",
                    "Recruitment Fraud"
                ]:
                    continue

            key = (
                item["category"],
                match.start(),
                match.end()
            )

            if key in checked:
                continue

            checked.add(key)

            evidence.append({
                "matched_text": match.group(0),
                "category": item["category"],
                "severity": item["severity"],
                "explanation": item["explanation"]
            })

    return evidence


# ---------------- RISK SCORING ----------------

def calculate_risk(fake_probability):

    risk_score = round(fake_probability * 100, 2)

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return risk_score, risk_level


def calculate_evidence_risk(evidence):

    evidence_score = 0

    weights = {
        "Payment Request": 75,
        "Payment Scam": 75,
        "Sensitive Information": 75,
        "Recruitment Fraud": 75,
        "Recruitment Process": 20,
        "Suspicious Recruitment": 20,
        "Unrealistic Promise": 20,
        "Urgency Pressure": 15,
        "Pressure Tactics": 15,
        "Salary Claim": 5
    }

    for item in evidence:

        category = item["category"]

        evidence_score += weights.get(category, 10)

    return min(evidence_score, 100)


# ---------------- SAFETY RECOMMENDATIONS ----------------

def generate_recommendations(prediction, evidence):

    recommendations = []

    categories = {
        item["category"] for item in evidence
    }

    if categories.intersection({
        "Payment Request",
        "Payment Scam",
        "Recruitment Fraud"
    }):
        recommendations.append(
            "Do not pay registration, processing or security fees "
            "without independently verifying the employer."
        )

    if "Sensitive Information" in categories:
        recommendations.append(
            "Never share OTPs, passwords or sensitive banking details."
        )

    if categories.intersection({
        "Recruitment Process",
        "Suspicious Recruitment"
    }):
        recommendations.append(
            "Verify the recruitment process through the company's "
            "official careers website."
        )

    if "Unrealistic Promise" in categories:
        recommendations.append(
            "Check whether the salary and employment promises "
            "are realistic and supported by an official offer."
        )

    if "Urgency Pressure" in categories:
        recommendations.append(
            "Avoid making rushed decisions. Verify the vacancy "
            "through an official recruitment channel."
        )

    if prediction == 1:
        recommendations.append(
            "Do not proceed until you independently verify the "
            "employer and job advertisement."
        )
    else:
        recommendations.append(
            "Still verify the employer, recruiter and job offer "
            "before sharing personal information."
        )

    if not evidence:
        recommendations.append(
            "No matching warning phrases were found. "
            "This does not guarantee that the advertisement is genuine."
        )

    return recommendations


# ---------------- COMPANY TRUST CHECK ----------------

def check_company(
    company_name="",
    website="",
    recruiter_email="",
    job_text=""
):

    checks = []
    concerns = []

    company_name, website, recruiter_email = extract_company_details(
        company_name,
        website,
        recruiter_email,
        job_text
    )

    if company_name:
        checks.append("Company name detected: " + company_name)

    if website:

        parsed = urlparse(
            website if "://" in website else "https://" + website
        )

        domain = parsed.hostname or ""

        if not domain or "." not in domain:
            concerns.append("Website address appears invalid.")

        elif parsed.scheme != "https":
            concerns.append("Website does not use HTTPS.")

        else:
            checks.append("Website address uses HTTPS.")

        if domain and any(
            shortener in domain
            for shortener in ["bit.ly", "tinyurl.com", "t.co"]
        ):
            concerns.append("Website uses a URL-shortening service.")

    if recruiter_email:

        if "@" not in recruiter_email:
            concerns.append("Recruiter email format appears invalid.")

        else:
            email_domain = recruiter_email.rsplit("@", 1)[1].lower()

            if email_domain in FREE_EMAIL_DOMAINS:
                concerns.append(
                    "Recruiter uses a public email provider, "
                    "not a confirmed company domain."
                )
            else:
                checks.append("Recruiter email uses a custom domain.")

    if not company_name and not website and not recruiter_email:
        status = "Not Provided"

    elif concerns:
        status = "Needs Review"

    else:
        status = "Not Independently Verified"

    return {
        "status": status,
        "company_name": company_name or "Not provided",
        "website": website or "Not provided",
        "recruiter_email": recruiter_email or "Not provided",
        "checks": checks,
        "concerns": concerns,
        "disclaimer": (
            "These are basic input checks, not official company verification. "
            "A real company or website has not been independently confirmed."
        )
    }


# ---------------- DASHBOARD ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- IMAGE UPLOAD ----------------

@app.route("/upload", methods=["POST"])
def upload_images():

    if "images" not in request.files:
        return jsonify({"error": "No images selected"}), 400

    files = request.files.getlist("images")
    saved_images = []

    for file in files:

        if file and file.filename and allowed_file(file.filename):

            filename = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"

            file.save(UPLOAD_FOLDER / unique_name)
            saved_images.append(unique_name)

    if not saved_images:
        return jsonify({"error": "No valid images uploaded"}), 400

    return jsonify({
        "message": "Images uploaded successfully",
        "total_images": len(saved_images),
        "images": saved_images
    })


# ---------------- OCR TEXT EXTRACTION ----------------

@app.route("/extract-text", methods=["POST"])
def extract_text():

    if "images" not in request.files:
        return jsonify({"error": "No images received"}), 400

    files = request.files.getlist("images")
    extracted_text = []

    for file in files:

        if not file or not file.filename:
            continue

        if not allowed_file(file.filename):
            continue

        try:
            image = Image.open(file.stream).convert("RGB")

            text = pytesseract.image_to_string(
                image,
                config="--psm 3"
            )

            extracted_text.append({
                "filename": file.filename,
                "text": text.strip(),
                "status": "success" if text.strip() else "no_text"
            })

        except Exception as error:

            extracted_text.append({
                "filename": file.filename,
                "text": "",
                "status": "error",
                "error": str(error)
            })

    if not extracted_text:
        return jsonify({"error": "No valid images found"}), 400

    return jsonify({
        "message": "OCR processing completed",
        "total_images": len(extracted_text),
        "results": extracted_text
    })


# ---------------- AI PREDICTION ----------------

@app.route("/predict", methods=["POST"])
def predict_job():

    data = request.get_json(silent=True)

    if not data or not isinstance(data.get("text"), str):
        return jsonify({
            "error": "Please provide job advertisement text"
        }), 400

    job_description = data["text"].strip()

    if not job_description:
        return jsonify({
            "error": "Job advertisement text cannot be empty"
        }), 400

    # Read optional company information
    company_name = str(data.get("company_name") or "").strip()
    company_website = str(data.get("company_website") or "").strip()
    recruiter_email = str(data.get("recruiter_email") or "").strip()

    # Extract company information
    company_name, company_website, recruiter_email = (
        extract_company_details(
            company_name,
            company_website,
            recruiter_email,
            job_description
        )
    )

    website_domain = extract_website_domain(company_website)

    # AI model prediction
    model_prediction = int(model.predict([job_description])[0])

    probabilities = model.predict_proba([job_description])[0]

    fake_probability = float(probabilities[1])
    model_confidence = round(
        float(probabilities[model_prediction]) * 100, 2
    )

    model_result = (
        "Fake Job" if model_prediction == 1 else "Genuine Job"
    )

    # Scam evidence detection
    evidence = analyze_evidence(job_description)

    # Calculate ML risk
    ml_risk_score = round(fake_probability * 100, 2)

    # Calculate evidence risk
    evidence_risk_score = calculate_evidence_risk(evidence)

    # Final risk score uses the stronger warning signal
    risk_score = max(
        ml_risk_score,
        evidence_risk_score
    )

    # Final prediction
    prediction = 1 if risk_score >= 70 else 0

    result = "Fake Job" if prediction == 1 else "Genuine Job"

    # Confidence: model probability for the final prediction class
    if prediction == 1:
        confidence = round(fake_probability * 100, 2)
    else:
        confidence = round((1 - fake_probability) * 100, 2)

    # Risk level
    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Safety recommendations
    recommendations = generate_recommendations(
        prediction,
        evidence
    )

    # Company trust report
    company_report = check_company(
        company_name,
        company_website,
        recruiter_email,
        job_description
    )

    reasons = [
        item["explanation"] for item in evidence
    ]

    if not reasons:
        reasons = ["No matching warning phrases were identified."]

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save scan history and network indicators
    with get_db() as connection:

        cursor = connection.execute("""
            INSERT INTO scan_history
            (
                job_text,
                prediction,
                label,
                confidence,
                risk_level,
                reasons,
                scan_date,
                recruiter_email,
                website_domain
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            job_description,
            result,
            prediction,
            confidence,
            risk_level,
            " | ".join(reasons),
            scan_date,
            recruiter_email or None,
            website_domain or None
        ))

        scan_id = cursor.lastrowid

    # Complete report
    return jsonify({
        "scan_id": scan_id,
        "prediction": result,
        "label": prediction,
        "model_prediction": model_result,
        "model_confidence": model_confidence,
        "confidence": confidence,
        "fake_probability": round(fake_probability * 100, 2),
        "ml_risk_score": ml_risk_score,
        "evidence_risk_score": evidence_risk_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "evidence": evidence,
        "reasons": reasons,
        "recommendations": recommendations,
        "company_report": company_report,
        "scan_date": scan_date
    })


# ---------------- DASHBOARD STATISTICS ----------------

@app.route("/stats")
def stats():

    with get_db() as connection:

        total = connection.execute(
            "SELECT COUNT(*) FROM scan_history"
        ).fetchone()[0]

        fake = connection.execute(
            "SELECT COUNT(*) FROM scan_history WHERE label = 1"
        ).fetchone()[0]

        genuine = connection.execute(
            "SELECT COUNT(*) FROM scan_history WHERE label = 0"
        ).fetchone()[0]

        high_risk = connection.execute(
            "SELECT COUNT(*) FROM scan_history WHERE risk_level = 'High'"
        ).fetchone()[0]

    return jsonify({
        "total_scans": total,
        "fake_jobs": fake,
        "genuine_jobs": genuine,
        "high_risk": high_risk
    })


# ---------------- SCAN HISTORY ----------------

@app.route("/history")
def history():

    with get_db() as connection:

        rows = connection.execute("""
            SELECT id, job_text, prediction, confidence,
                   risk_level, reasons, scan_date,
                   recruiter_email, website_domain
            FROM scan_history
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()

    history_items = [dict(row) for row in rows]

    return jsonify({
        "total": len(history_items),
        "history": history_items
    })


# ---------------- SCAM PATTERN NETWORK ----------------

@app.route("/network")
def scam_network():

    with get_db() as connection:

        rows = connection.execute("""
            SELECT id, prediction, label, risk_level,
                   recruiter_email, website_domain, scan_date
            FROM scan_history
            ORDER BY id DESC
        """).fetchall()

    scans = [dict(row) for row in rows]

    nodes = []
    links = []

    email_counts = {}
    domain_counts = {}

    # Count repeated email addresses and domains
    for scan in scans:

        email = (scan["recruiter_email"] or "").strip().lower()
        domain = (scan["website_domain"] or "").strip().lower()

        if email:
            email_counts[email] = email_counts.get(email, 0) + 1

        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

    repeated_indicators = []

    for email, count in email_counts.items():

        if count >= 2:
            repeated_indicators.append({
                "type": "recruiter_email",
                "value": email,
                "scan_count": count,
                "message": "This recruiter email appears in multiple scans."
            })

    for domain, count in domain_counts.items():

        if count >= 2:
            repeated_indicators.append({
                "type": "website_domain",
                "value": domain,
                "scan_count": count,
                "message": "This website domain appears in multiple scans."
            })

    # Create job nodes and connections
    for scan in scans:

        scan_id = scan["id"]
        job_node_id = f"job-{scan_id}"

        nodes.append({
            "id": job_node_id,
            "type": "job",
            "label": f"Job Scan #{scan_id}",
            "prediction": scan["prediction"],
            "risk_level": scan["risk_level"],
            "scan_date": scan["scan_date"]
        })

        email = (scan["recruiter_email"] or "").strip().lower()
        domain = (scan["website_domain"] or "").strip().lower()

        if email:

            email_node_id = "email-" + email

            links.append({
                "source": job_node_id,
                "target": email_node_id,
                "type": "recruiter_email"
            })

        if domain:

            domain_node_id = "domain-" + domain

            links.append({
                "source": job_node_id,
                "target": domain_node_id,
                "type": "website_domain"
            })

    # Add unique indicator nodes
    for email, count in email_counts.items():

        nodes.append({
            "id": "email-" + email,
            "type": "recruiter_email",
            "label": email,
            "shared": count >= 2,
            "scan_count": count
        })

    for domain, count in domain_counts.items():

        nodes.append({
            "id": "domain-" + domain,
            "type": "website_domain",
            "label": domain,
            "shared": count >= 2,
            "scan_count": count
        })

    return jsonify({
        "total_scans": len(scans),
        "total_nodes": len(nodes),
        "total_connections": len(links),
        "repeated_indicators": repeated_indicators,
        "repeated_indicator_count": len(repeated_indicators),
        "nodes": nodes,
        "links": links,
        "message": (
            "Repeated contact details and website domains are "
            "indicators for further investigation, not proof of fraud."
        )
    })


# ---------------- HEALTH CHECK ----------------

@app.route("/health")
def health():

    return jsonify({
        "status": "running",
        "project": "JobShield AI",
        "ocr": "enabled",
        "model": "real_dataset_model_loaded",
        "database": "enabled",
        "evidence_engine": "enabled",
        "risk_scoring": "enabled",
        "company_checks": "basic_checks_enabled",
        "scam_network": "enabled"
    })


# ---------------- ERROR HANDLING ----------------

@app.errorhandler(413)
def file_too_large(error):

    return jsonify({
        "error": "Uploaded files are too large. Please use smaller images."
    }), 413


if __name__ == "__main__":
    app.run(debug=True)
