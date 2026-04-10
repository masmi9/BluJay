from flask import Flask
from dashboard.routes import dashboard_bp

def create_app():
    app = Flask(__name__)
    app.config.update (
        SECRET_KEY="dev",
        UPLOAD_FOLDER = "/tmp/blujay_uploads",
        MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB limit
    )
    app.register_blueprint(dashboard_bp)
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
