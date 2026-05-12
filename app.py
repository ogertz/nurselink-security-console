from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from groq import Groq
import sqlite3
import os
from datetime import datetime
import textwrap

app = Flask(__name__)

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.isdir(dotenv_path):
    dotenv_path = os.path.join(dotenv_path, ".env")
load_dotenv(dotenv_path)

# Configure Gemini
# Configure Groq
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Initialize database
def init_db():
    conn = sqlite3.connect("incidents.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT,
            severity TEXT,
            hipaa_controls TEXT,
            risk_score TEXT,
            remediation TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def analyze_incident(description):
    prompt = textwrap.dedent(f"""
        You are a HIPAA and NIST 800-30 compliance expert for a healthcare startup called NurseLink, an Uber-for-nurses platform that handles Protected Health Information (PHI).

        Analyze this security incident and respond in exactly this format with these exact headers:

        SEVERITY: [Critical/High/Medium/Low]
        
        HIPAA CONTROLS VIOLATED:
        - List each specific HIPAA control violated with its section number (e.g. §164.312(a)(1) Access Control)
        - Be specific and cite real HIPAA Security Rule sections
        
        NIST 800-30 RISK SCORE:
        - Likelihood: [1-5] - [brief justification]
        - Impact: [1-5] - [brief justification]
        - Overall Risk: [Low/Moderate/High/Very High]
        
        REMEDIATION STEPS:
        - List 4-5 specific actionable remediation steps
        - Reference relevant HIPAA controls in each step
        
        POLICY RECOMMENDATION:
        - One specific policy that NurseLink should implement to prevent recurrence

        Incident Description: {description}
    """)

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024
    )
    return response.choices[0].message.content

def parse_response(response_text):
    result = {
        "severity": "Unknown",
        "hipaa_controls": "",
        "risk_score": "",
        "remediation": "",
        "policy": "",
        "raw": response_text
    }

    lines = response_text.strip().split('\n')
    current_section = None
    section_content = []

    for line in lines:
        clean = line.strip().lstrip('#').lstrip('*').strip()
        
        if 'SEVERITY' in clean.upper() and ':' in clean:
            result["severity"] = clean.split(':', 1)[1].strip().replace('*', '').replace('#', '')
        elif 'HIPAA CONTROLS' in clean.upper():
            current_section = "hipaa"
            section_content = []
        elif 'NIST 800-30' in clean.upper() or 'RISK SCORE' in clean.upper():
            if current_section == "hipaa":
                result["hipaa_controls"] = "\n".join(section_content)
            current_section = "risk"
            section_content = []
        elif 'REMEDIATION' in clean.upper():
            if current_section == "risk":
                result["risk_score"] = "\n".join(section_content)
            current_section = "remediation"
            section_content = []
        elif 'POLICY RECOMMENDATION' in clean.upper():
            if current_section == "remediation":
                result["remediation"] = "\n".join(section_content)
            current_section = "policy"
            section_content = []
        elif clean and current_section:
            section_content.append(clean)

    if current_section == "policy" and section_content:
        result["policy"] = "\n".join(section_content)
    elif current_section == "remediation" and section_content:
        result["remediation"] = "\n".join(section_content)

    return result

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    description = data.get("description", "")
    
    if not description:
        return jsonify({"error": "No incident description provided"}), 400
    
    try:
        response_text = analyze_incident(description)
        parsed = parse_response(response_text)
        
        # Save to database
        conn = sqlite3.connect("incidents.db")
        c = conn.cursor()
        c.execute("""
            INSERT INTO incidents (description, severity, hipaa_controls, risk_score, remediation, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            description,
            parsed["severity"],
            parsed["hipaa_controls"],
            parsed["risk_score"],
            parsed["remediation"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()
        
        return jsonify(parsed)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/history")
def history():
    conn = sqlite3.connect("incidents.db")
    c = conn.cursor()
    c.execute("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 10")
    rows = c.fetchall()
    conn.close()
    
    incidents = []
    for row in rows:
        incidents.append({
            "id": row[0],
            "description": row[1],
            "severity": row[2],
            "hipaa_controls": row[3],
            "risk_score": row[4],
            "remediation": row[5],
            "timestamp": row[6]
        })

    return jsonify({"incidents": incidents})

if __name__ == "__main__":
    load_dotenv()
    init_db()
    app.run(debug=True)
