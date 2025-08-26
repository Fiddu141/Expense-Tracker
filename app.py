import os
from flask import Flask, render_template, request, redirect, url_for, flash

UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
ALLOWED_EXTENSIONS = {"txt", "pdf", "epub", "mobi"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = "supersecretkey"  # In production, load from env var

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    if "book" not in request.files:
        flash("No file part")
        return redirect(url_for("index"))
    file = request.files["book"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("index"))
    if file and allowed_file(file.filename):
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)
        flash("Book uploaded successfully!")
    else:
        flash("File type not allowed")
    return redirect(url_for("index"))

@app.route("/search", methods=["POST"])
def search():
    query = request.form.get("query", "").strip()
    if query:
        answer = "This is a generic answer to any definition query."
    else:
        answer = "Please enter a definition to search."
    return render_template("index.html", answer=answer)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)