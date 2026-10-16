# AI-Based Phishing URL Detection System Using Machine Learning

> **Final Year Bachelor of Computer Applications (BCA) Capstone Project**  
> An enterprise-grade, full-stack cybersecurity web application that performs real-time lexical threat analysis on untrusted URLs using supervised machine-learning algorithms, calibrated risk scoring, and automated PDF audit certification.

---

## 1. System Architecture & Tech Stack

```
                              ┌──────────────────────────────────────────────┐
                              │            Web Browser (Client)              │
                              │  Bootstrap 5 • Chart.js • HTML5 / CSS3 / JS  │
                              └──────────────────────┬───────────────────────┘
                                                     │ HTTP / REST / CSRF
                                                     ▼
                              ┌──────────────────────────────────────────────┐
                              │            Flask Application Factory         │
                              │      Session Auth • Role Access Control      │
                              └──────┬───────────────┬───────────────┬───────┘
                                     │               │               │
            ┌────────────────────────┴────┐          │          ┌────┴────────────────────────┐
            ▼                             ▼          │          ▼                             ▼
┌───────────────────────┐   ┌──────────────────────┐ │ ┌─────────────────────┐   ┌───────────────────────────┐
│ Zero-Execution Engine │   │   ML Ops Pipeline    │ │ │  ReportLab Generator│   │ MySQL 8.x (Relational DB) │
│ • 13 Lexical Signals  │   │ • Random Forest      │ │ │ • PDF Audit Certs   │   │ • PyMySQL Driver          │
│ • Token Extraction    │   │ • Logistic Regression│ │ │ • Formula-Safe CSV  │   │ • Flask-Migrate / Alembic │
│ • No Outbound Traffic │   │ • Decision Tree      │ │ │   Exports           │   │ • 7 Relational Entities   │
└───────────────────────┘   │ • Auto Model Selector│ │ └─────────────────────┘   └───────────────────────────┘
                            └──────────────────────┘ ┘
```

- **Backend Framework:** Python 3.12+ / Flask (Application Factory Pattern)
- **Mandatory Database:** MySQL 8.x using PyMySQL and Flask-SQLAlchemy (with SQLite test fallback)
- **Database Migrations:** Flask-Migrate & Alembic
- **Machine Learning:** Scikit-Learn, Pandas, NumPy, Joblib
- **Authentication & Security:** Flask-Login, Werkzeug Password Hashing, Flask-WTF (CSRF Protection), IDOR Prevention, Spreadsheet Formula Injection Neutralization
- **Reporting & Data Export:** ReportLab (Vector PDF Audit Reports), Python CSV Module (Formula-Sanitized CSV)
- **Frontend & Data Visualization:** HTML5, CSS3 (Cybersecurity Dark Navy Theme), Bootstrap 5, Chart.js
- **Automated Testing:** Pytest (19 unit and integration tests passing)

---

## 2. Entity-Relationship (ER) Diagram

The system implements a relational schema across 7 MySQL tables with foreign keys, cascading delete rules, unique constraints, and search indexes:

```mermaid
erDiagram
    users ||--o{ scans : "performs (1:N, cascade)"
    users ||--o{ datasets : "uploads (1:N, set-null)"
    users ||--o{ training_runs : "initiates (1:N, set-null)"
    users ||--o{ audit_logs : "generates (1:N, set-null)"
    scans ||--|| scan_features : "extracts (1:1, cascade)"
    models ||--o{ scans : "predicts (1:N, set-null)"
    datasets ||--o{ training_runs : "trains (1:N, cascade)"
    models ||--o{ training_runs : "evaluates (1:N, set-null)"

    users {
        int id PK
        string username UK "Indexed"
        string email UK "Indexed"
        string password_hash
        string role "user | admin, Indexed"
        boolean is_active_account
        datetime created_at
        datetime updated_at
    }

    scans {
        int id PK
        int user_id FK "users.id (CASCADE)"
        text url
        string url_hash "SHA-256 Indexed"
        string prediction_label "phishing | legitimate"
        float risk_score "0.0 - 100.0"
        string risk_category "Low | Moderate | High | Critical"
        float probability "0.0 - 1.0"
        string model_version
        int model_id FK "models.id (SET NULL)"
        float latency_ms
        text explanation_json
        datetime created_at "Indexed"
    }

    scan_features {
        int id PK
        int scan_id FK "scans.id (CASCADE, UK)"
        int url_length
        int hostname_length
        int num_dots
        int num_hyphens
        int num_digits
        int num_subdomains
        int is_https
        int is_ip
        int suspicious_token_count
        int path_length
        int query_length
        int has_at_symbol
        int percent_encoded_count
        datetime created_at
    }

    datasets {
        int id PK
        string original_filename
        string storage_filename UK
        string file_hash "SHA-256 Indexed"
        int file_size_bytes
        string upload_status "valid | invalid"
        int total_rows
        int phishing_count
        int legitimate_count
        int duplicate_rows
        int missing_values_count
        text validation_errors_json
        int uploaded_by_id FK "users.id (SET NULL)"
        datetime created_at "Indexed"
    }

    models {
        int id PK
        string name
        string algorithm "Indexed"
        string version UK "Indexed"
        string artifact_path
        boolean is_active "Indexed"
        text feature_names_json
        text hyperparameters_json
        float accuracy
        float precision_score
        float recall_score
        float f1_score
        float roc_auc
        text confusion_matrix_json
        float avg_latency_ms
        float training_time_sec
        float selection_score
        text selection_notes
        datetime created_at "Indexed"
        datetime updated_at
    }

    training_runs {
        int id PK
        int dataset_id FK "datasets.id (CASCADE)"
        int model_id FK "models.id (SET NULL)"
        string run_identifier UK "Indexed"
        string status "running | completed | failed"
        int evaluated_models_count
        string selected_model_name
        text evaluation_summary_json
        text selection_reason
        text error_message
        int initiated_by_id FK "users.id (SET NULL)"
        datetime created_at "Indexed"
        datetime completed_at
    }

    audit_logs {
        int id PK
        int user_id FK "users.id (SET NULL)"
        string action "Indexed"
        text details
        string ip_address
        datetime created_at "Indexed"
    }
```

---

## 3. Database Initialization & Setup

### Option A: MySQL 8.x Configuration (Production / Evaluation Standard)

1. Ensure MySQL Server 8.x is running locally or remotely.
2. Connect to MySQL client as `root` and create the dedicated database:
   ```sql
   CREATE DATABASE IF NOT EXISTS phishing_detection_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER IF NOT EXISTS 'phish_user'@'localhost' IDENTIFIED BY 'SecurePass2026!';
   GRANT ALL PRIVILEGES ON phishing_detection_db.* TO 'phish_user'@'localhost';
   FLUSH PRIVILEGES;
   ```
3. Update your `.env` configuration file:
   ```ini
   DATABASE_URL=mysql+pymysql://phish_user:SecurePass2026!@localhost:3306/phishing_detection_db
   ```
4. Run database migrations to apply the schema:
   ```bash
   ./venv/bin/flask db upgrade
   ```

### Option B: Local SQLite Quick-Start (Standalone Evaluation Fallback)
If evaluating on a portable system without a running MySQL daemon:
```ini
DATABASE_URL=sqlite:///phishing_detection.db
```
The application dynamically detects the dialect and executes identical relational constraints.

---

## 4. Installation & Quick Start

### 1. Clone repository & enter directory
```bash
git clone <repo-url>
cd <repo-dir>
```

### 2. Create and activate Python virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment
```bash
cp .env.example .env
```

### 5. Initialize Database & Create Initial Administrator
Never hardcode admin accounts. Use the secure CLI prompt:
```bash
python -m flask create-admin
# Enter username: admin
# Enter email: admin@cybersecurity.edu
# Enter password: (hidden prompt)
```

### 6. Seed Academic Demo Dataset & Baseline Trained Models
Populate the system with verified demonstration data:
```bash
python -m flask seed-demo-data
```
This automatically:
- Generates a verified academic sample dataset with 100 balanced URLs.
- Executes the ML training pipeline across Random Forest, Logistic Regression, and Decision Tree.
- Benchmarks evaluation metrics on a held-out test split.
- Automatically selects and activates the top-performing model.

### 7. Launch Web Server
```bash
python run.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your web browser.

---

## 5. Machine Learning & Zero-Execution Lexical Engine

### Zero Outbound Execution Guarantee
Standard phishing scanners often visit or execute remote URLs, exposing the server to zero-day browser exploits, triggering attacker alerting beacons, or executing malicious JavaScript.  
**PhishShield AI executes 100% offline lexical feature extraction**: no DNS lookups, no HTTP requests, and no socket connections are made to the analyzed target.

### 13 Extracted Lexical Indicators
| Feature Name | Type | Cybersecurity Significance |
|---|---|---|
| `url_length` | Integer | Phishing links often exceed 75 characters to hide malicious redirection strings. |
| `hostname_length` | Integer | Domain length analysis detects deceptive typosquatting. |
| `num_dots` | Integer | Multi-tier spoofed domains feature excessive dot counts (`.` >= 4). |
| `num_hyphens` | Integer | Attackers frequently separate keywords with hyphens (e.g. `paypal-security-alert`). |
| `num_digits` | Integer | High digit counts correlate with automated algorithmically generated domains (DGA). |
| `num_subdomains` | Integer | Subdomain padding tricks mobile browsers where long URLs truncate the address bar. |
| `is_https` | Binary (0/1) | Verifies scheme. **HTTPS does NOT guarantee legitimacy**, as modern phishing sites routinely use free Let's Encrypt certificates. |
| `is_ip` | Binary (0/1) | Detects raw IPv4/IPv6 host literals used to bypass domain reputation checks. |
| `suspicious_token_count` | Integer | Matches sensitive keywords (`login`, `verify`, `update`, `banking`, `appleid`, `wallet`, etc.). |
| `path_length` | Integer | Deep folder hierarchies used to evade shallow directory blocklists. |
| `query_length` | Integer | Length of GET parameters carrying encoded tokens and target email addresses. |
| `has_at_symbol` | Binary (0/1) | The `@` symbol causes web browsers to discard preceding text as user info, redirecting to the host after the `@`. |
| `percent_encoded_count` | Integer | Hex-encoding percentage (`%20`, `%2F`) used to obfuscate suspicious string tokens. |

### Supervised Candidate Algorithms
1. **Random Forest Classifier (`n_estimators=100, max_depth=12`):**
   - Ensemble of bagged decision trees with feature sub-sampling. Superior non-linear interaction modeling with high resilience against overfitting.
2. **Logistic Regression (`max_iter=1000, C=1.0`):**
   - L2-regularized linear model trained on standardized feature vectors. Provides high interpretability and extremely fast sub-millisecond inference.
3. **Decision Tree Classifier (`max_depth=8`):**
   - White-box rule-based classifier providing transparent rule tree traversals.

### Anti-Data Leakage Protocol
- The dataset is split into **75% Training** and **25% Held-Out Testing** using stratified sampling (`stratify=y, random_state=42`).
- `StandardScaler` is fitted **strictly on the training partition** and applied via transformation to the test partition and subsequent runtime inference.
- Reported metrics represent held-out test performance—**never training accuracy**.

### Automatic Model Selector
Eligible models must satisfy strict baseline gates:
- **Minimum Recall Threshold:** $\ge 80.0\%$ (prioritizing the minimization of False Negatives in threat detection).
- **Maximum Inference Latency Ceiling:** $\le 100.0\text{ ms}$.

Models passing both gates are ranked via the composite selection score:
$$\text{Score} = (0.40 \times \text{Recall}) + (0.30 \times F_1) + (0.20 \times \text{Precision}) + \left(0.10 \times \max\left(0, 1 - \frac{\text{Latency}}{\text{Max Latency}}\right)\right)$$

Deterministic tie-breaking prioritizes:
1. Higher Composite Selection Score
2. Higher Phishing Recall
3. Higher F1-Score
4. Lower Average Latency

---

## 6. Security & Defensive Architecture

- **Role-Based Access Control (RBAC):** Server-side verification via `@login_required` and `@admin_required` decorators.
- **Insecure Direct Object Reference (IDOR) Protection:** Users can access only their own scan records, certificates, and CSV files. Cross-tenant access returns `HTTP 403 Forbidden`.
- **CSRF Defense:** Mandatory CSRF token enforcement on all state-modifying requests (`POST`).
- **Spreadsheet Formula Injection Sanitization:** Cell values starting with `=cmd`, `+`, `-`, or `@` are escaped with a leading single quote before CSV generation to protect against spreadsheet macro execution exploits.
- **Safe Output Escaping:** Monospace rendering with URL wrapping to neutralize cross-site scripting (XSS).

---

## 7. Viva Demonstration Walkthrough

| Step | Persona | Action | Expected Output |
|---|---|---|---|
| **1. Registration & Auth** | User | Register as `analyst_jane` and sign in. | Redirected to User Dashboard with 0 scans recorded. |
| **2. Real-Time Scan** | User | Enter `http://192.168.1.50/paypal-security/login.php?update=verify@bank`. | Instant classification: **PHISHING**, Risk Score: **90+ / 100 (Critical)**. Suspicious tokens and IP host flagged. |
| **3. PDF Audit Download** | User | Click **Download PDF Audit Certificate**. | ReportLab generates vector PDF with unique audit ID, features table, latency, and disclaimer. |
| **4. Personal CSV Export** | User | Click **Export My Scans (CSV)** from dashboard. | CSV download containing exclusively `analyst_jane`'s records. |
| **5. IDOR Verification** | User | Try to open `/scan/<other_user_id>`. | Handled with **403 Forbidden** error page. |
| **6. Admin Portal Access** | Admin | Sign in with CLI-created administrator account. | Global metrics, user management, and ML Ops tools enabled. |
| **7. Dataset Validation** | Admin | Upload new CSV dataset via `/admin/datasets/upload`. | Validation preview: row count, duplicate analysis, and class balance verified. |
| **8. Multi-Model Pipeline** | Admin | Click **Start Model Training Pipeline**. | Trains Random Forest, Logistic Regression, and Decision Tree on held-out test split. |
| **9. Model Comparison** | Admin | View `/admin/model-comparison`. | Dynamic Chart.js bar chart, comparison table, and confusion matrix grid displayed. |
| **10. Manual Model Toggle**| Admin | Click **Make Active** on Logistic Regression. | Production traffic routes to Logistic Regression; audit log event recorded. |

---

## 8. Automated Testing

Run the comprehensive test suite verifying authentication, authorization, feature extraction, ML training, IDOR protection, and report generation:

```bash
./venv/bin/pytest -v -o pythonpath=.
```

**Test Suite Coverage (19 Tests Passing):**
- `test_unauthenticated_access_redirect`
- `test_regular_user_forbidden_from_admin_portal`
- `test_admin_user_permitted_on_admin_portal`
- `test_password_hashing`
- `test_user_registration`
- `test_user_login_and_logout`
- `test_cli_admin_creation`
- `test_feature_names_order_and_count`
- `test_ip_address_detection`
- `test_subdomain_counting`
- `test_lexical_feature_extraction_phishing_url`
- `test_training_pipeline_and_model_selection`
- `test_model_selector_rejection_and_ranking`
- `test_csv_formula_injection_sanitization`
- `test_pdf_audit_generation_and_idor_protection`
- `test_user_csv_export_isolation`
- `test_risk_category_thresholds`
- `test_url_scan_and_database_persistence`
- `test_scan_route_submission`

---

## 9. Academic Disclaimer & Technical Limitations

1. **Statistical Prediction:** Classifications represent statistical machine-learning approximations based on static lexical indicators. Zero claims of absolute phishing immunity or infallibility are made.
2. **HTTPS Padlock Notice:** The presence of HTTPS indicates encrypted transport between client and server; it does **not** authenticate destination legitimacy. Phishers routinely obtain valid SSL/TLS certificates.
3. **Zero Outbound Execution:** This system intentionally does not follow HTTP redirects, scrape DOM trees, or execute payload scripts to guarantee operator server isolation and safety.
