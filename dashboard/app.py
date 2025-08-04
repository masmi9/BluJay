from flask import Flask
from dashboard.routes import dashboard_bp

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 160 * 1024 * 1024  # 160 MB limit
app.register_blueprint(dashboard_bp)

if __name__ == "__main__":
    app.run(debug=True)
