import json
import os
import shutil
import uuid
from pathlib import Path
from flask import Blueprint, render_template, request, redirect, url_for, current_app, flash
from werkzeug.utils import secure_filename

from core.analyzer import Analyzer

dashboard_bp = Blueprint("dashboard", __name__)

ALLOWED_LANGUES = ['python', 'java']
ALLOWED_SINGLE_FILE = {".java", ".py"}
ALLOWED_ARCHIVE = {".zip", ".jar"} # jar is a zip container

def _ensure_file(p: str) -> None:
    Path(p).mkdir(parents=True, exist_ok=True)

def _save_upload(file_storage, base_dir: str) -> str:
    _ensure_file(base_dir)
    fname = secure_filename(file_storage.filename or f"upload-{uuid.uuid4().hex}")
    dest = os.path.join(base_dir, fname)
    file_storage.save(dest)
    return dest

def _extract_if_needed(src_path: str, dest_root:str) -> str:
    ext = (Path(src_path).suffix.lower())
    if ext in ALLOWED_ARCHIVE:
        extract_dir = os.path.join(dest_root, Path(src_path).stem)
        _ensure_file(extract_dir)
        # shutil can unpack zip/jar; jar is ZIP format
        shutil.unpack_archive(src_path, extract_dir)
        return extract_dir
    return src_path

def _write_results(job_dir: str, results: list) -> None:
    out_path = os.path.join(job_dir, "results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return out_path

@dashboard_bp.route("/", methods=["GET"])
def index():
    return render_template('index.html')

@dashboard_bp.route("/scan", methods=["POST"])
def run_scan():
    uploaded_file = request.files.get('source_file')
    language = (request.form.get('language') or "").strip().lower()

    if not uploaded_file or not uploaded_file.filename:
        flash("Please choose a file to scan.", "error")
        return redirect(url_for('dashboard.index'))
    
    if language not in ALLOWED_LANGUES:
        flash(f"Unsupported language: {language}", "error")
        return redirect(url_for('dashboard.index'))
    
    # Create a job workspace
    job_id = uuid.uuid4().hex
    base_upload_dir = current_app.config.get("UPLOAD_FOLDER", "/tmp/blujay_uploads")
    job_dir = os.path.join(base_upload_dir, job_id)
    _ensure_file(job_dir)

    try:
        saved_path = _save_upload(uploaded_file, job_dir)
        # Optional: enforce allowed file types to avoid confusion
        ext = Path(saved_path).suffix.lower()
        if ext not in (ALLOWED_SINGLE_FILE | ALLOWED_ARCHIVE):
            flash(f"Unsupported file type: {ext}", "error")
            return redirect(url_for('dashboard.index'))
        
        scan_target = _extract_if_needed(saved_path, job_dir)
        analyzer = Analyzer(language=language)
        results = analyzer.analyze(scan_target)

        _write_results(job_dir, results)
        return redirect(url_for('dashboard.results', job_id=job_id))
    
    except Exception as e:
        # Log and surface a friendly message
        current_app.logger.exception("Error during scan")
        flash(f"An error occurred during scanning: {str(e)}", "error")
        return redirect(url_for('dashboard.index'))
    
@dashboard_bp.route("/results/<job_id>", methods=["GET"])
def results(job_id):
    base_upload_dir = current_app.config.get("UPLOAD_FOLDER", "/tmp/blujay_uploads")
    job_dir = os.path.join(base_upload_dir, job_id)
    results_path = os.path.join(job_dir, "results.json")
    
    if not os.path.exists(results_path):
        flash("Results not found for the given job ID.", "error")
        return redirect(url_for('dashboard.index'))
    
    with open(results_path, "r", encoding="utf-8") as f:
        results = json.load(f)
    
    # Sort by severity if available, else leave as-is
    def sev_rank(item):
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item.get("severity", "").lower(), 99)

    findings_sorted = sorted(results, key=sev_rank)
    return render_template('results.html', job_id=job_id, findings=findings_sorted)