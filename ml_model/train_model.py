import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = BASE_DIR / "dataset" / "real_job_posts.csv"
MODEL_PATH = BASE_DIR / "ml_model" / "job_model.pkl"

print("=" * 55)
print("       JOBSHIELD AI - REAL DATASET TRAINING")
print("=" * 55)

# Load real dataset
df = pd.read_csv(DATASET_PATH)

# Text and information fields used for training
text_columns = [
    "title",
    "location",
    "department",
    "salary_range",
    "company_profile",
    "description",
    "requirements",
    "benefits",
    "employment_type",
    "required_experience",
    "required_education",
    "industry",
    "function",
    "telecommuting",
    "has_company_logo",
    "has_questions"
]

# Handle missing values
for column in text_columns:
    df[column] = df[column].fillna("").astype(str)

# Combine job information into one text field
df["combined_text"] = df[text_columns].agg(" ".join, axis=1)

# Remove records without useful text or a valid label
df = df[
    (df["combined_text"].str.strip() != "") &
    (df["fraudulent"].isin([0, 1]))
].copy()

X = df["combined_text"]
y = df["fraudulent"].astype(int)

print("\nTotal usable records:", len(df))
print("Genuine jobs:", (y == 0).sum())
print("Fake jobs:", (y == 1).sum())

# Split data while preserving class proportions
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Build the AI model
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            stop_words="english",
            max_features=50000,
            ngram_range=(1, 2),
            min_df=2,
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            random_state=42
        )
    )
])

# Train
print("\nTraining model...")
model.fit(X_train, y_train)

# Evaluate on unseen test data
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]

print("\n========== MODEL RESULTS ==========")

print(
    "Accuracy:",
    round(accuracy_score(y_test, predictions) * 100, 2),
    "%"
)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["Genuine Job", "Fake Job"],
        zero_division=0
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))

print(
    "\nROC-AUC:",
    round(roc_auc_score(y_test, probabilities), 4)
)

# Save trained model
joblib.dump(model, MODEL_PATH)

print("\nModel saved successfully!")
print("Location:", MODEL_PATH)
print("\nJobShield AI real-data training completed.")
