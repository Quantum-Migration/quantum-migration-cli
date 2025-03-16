from flask import Flask, request, jsonify
import os

app = Flask(__name__)
REPORTS_DIR = "reports"
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route('/upload_report', methods=['POST'])
def upload_report():
    data = request.get_json()
    report_text = data.get("report")
    if not report_text:
        return jsonify({"error": "No report provided"}), 400
    # Save the report to a file with a timestamp.
    from datetime import datetime
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = os.path.join(REPORTS_DIR, f"migration_report_{timestamp}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)
    return jsonify({"message": "Report received", "filename": filename}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
