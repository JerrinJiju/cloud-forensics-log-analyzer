from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import os
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet
from analyzer import analyze_log_file  # ✅ correct import

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Upload folder
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Dummy users (replace with DB if needed)
users = {"admin": "password", "user": "1234"}

# Store last report
last_report = {}
last_filename = ""


# ---------------- ROUTES ---------------- #

@app.route("/")
def home():
    """Home page"""
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in users and users[username] == password:
            session["user"] = username
            flash("Login successful!", "success")
            return redirect(url_for("upload"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout user"""
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """Upload log file"""
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file selected", "danger")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("No file selected", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Analyze file using analyzer.py
        global last_report, last_filename
        last_filename = filename
        last_report = analyze_log_file(filepath)   # ✅ fixed call

        return redirect(url_for("results"))

    return render_template("upload.html")


@app.route("/results")
def results():
    """Show analysis results"""
    if not last_report:
        flash("No report available. Please upload a file.", "warning")
        return redirect(url_for("upload"))
    return render_template("results.html", report=last_report, filename=last_filename)


# ✅ Updated PDF Download Route with Professional Header
@app.route("/download")
def download_report():
    """Download report as PDF"""
    if not last_report:
        flash("No report available to download.", "warning")
        return redirect(url_for("upload"))

    pdf_path = "report.pdf"
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Project header with divider line
    story.append(Paragraph("<b><font size=16>Cloud Forensic Log Analyzer</font></b>", styles["Title"]))
    story.append(Spacer(1, 5))
    story.append(HRFlowable(width="100%", thickness=2, color="black"))
    story.append(Spacer(1, 15))

    story.append(Paragraph("<b>Forensic Log Analysis Report</b>", styles["Heading2"]))
    story.append(Paragraph(f"<b>Analyzed File:</b> {last_filename}", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Add report contents
    for keyword, data in last_report.items():
        text = f"<b>{keyword}</b>: {data['count']} occurrences<br/><b>Suggested Solution:</b> {data['solution']}"
        story.append(Paragraph(text, styles["Normal"]))
        story.append(Spacer(1, 10))

    # Build and save the PDF
    doc.build(story)
    return send_file(pdf_path, as_attachment=True)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    """Feedback page"""
    if request.method == "POST":
        user_feedback = request.form["feedback"]
        with open("feedback.txt", "a") as f:
            f.write(user_feedback + "\n")
        flash("Thank you for your feedback!", "success")
        return redirect(url_for("home"))
    return render_template("feedback.html")


# ---------------- RUN APP ---------------- #

if __name__ == "__main__":
    app.run(debug=True)
