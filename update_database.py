# Create a file called update_database.py in your project root:
# update_database.py

from app import app, db

with app.app_context():
    # This will create all tables that don't exist yet
    db.create_all()
    print("Database updated successfully!")
    print("New tables created: comments")