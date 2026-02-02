import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Create database instance
db = SQLAlchemy()

# Create the Flask app
def create_app():
    app = Flask(__name__)
    
    # 1. Secret key
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    
    # 2. Database setup
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Fix for Render (postgres:// → postgresql://)
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    else:
        # Local SQLite
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # 3. File upload settings
    app.config['UPLOAD_FOLDER'] = 'static/uploads'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
    
    # 4. Initialize database with app
    db.init_app(app)
    
    # 5. Import routes (AFTER db is initialized)
    from . import routes
    app.register_blueprint(routes.bp)  # If using blueprints
    # OR: app = routes.register_routes(app) if you have a function
    
    # 6. Create tables
    with app.app_context():
        db.create_all()
        print("Database tables created!")
    
    return app

# Create app instance
app = create_app()