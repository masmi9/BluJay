from flask import Blueprint, render_template, request
from core.analyzer import Analyzer
import os
import shutil
from werkzeug.utils import secure_filename


dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/", methods=["GET", "POST"])
def index():
    results = []
    if request.method == "POST":
        uploaded_file = request.files.get('source_file')
        language = request.form.get('language')

        if uploaded_file and language:
            # Save to /tmp or uploads/
            filename = secure_filename(uploaded_file.filename)
            temp_path = os.path.join('/tmp', filename)
            uploaded_file.save(temp_path)

            analyzer = Analyzer(language=language)

            if temp_path.endswith('.zip'):
                extract_path = os.path.join('/tmp', filename.replace('.zip', ''))
                shutil.unpack_archive(temp_path, extract_path)
                results = analyzer.run(extract_path)
            else:
                results = analyzer.run(temp_path)
        else:
            print("[ERROR] File or language not provided.")

    return render_template('index.html', results=results)