import os
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_from_directory, session
)
from flask_sqlalchemy import SQLAlchemy
import secrets
import time

# ------------------- App Setup -------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Security settings
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session timeout: 2 hours
app.config['MAX_FAILED_LOGIN_ATTEMPTS'] = 5  # Lock after 5 failed attempts
app.config['ACCOUNT_LOCKOUT_MINUTES'] = 15   # Lock for 15 minutes
app.config['PASSWORD_RESET_TOKEN_EXPIRY'] = 3600  # 1 hour in seconds

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///documents.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ------------------- Context Processor -------------------
@app.context_processor
def inject_now():
    return {"now": datetime.utcnow}

@app.before_request
def check_session_timeout():
    """Check if session has timed out"""
    if 'user_id' in session:
        # Make session permanent
        session.permanent = True
        app.permanent_session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']

# ------------------- Association Tables -------------------
project_user = db.Table(
    "project_user",
    db.Column("project_id", db.Integer, db.ForeignKey("project.id")),
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"))
)

document_tag = db.Table(
    "document_tag",
    db.Column("document_id", db.Integer, db.ForeignKey("document.id")),
    db.Column("tag_id", db.Integer, db.ForeignKey("tag.id"))
)

# ------------------- Models -------------------
ROLES = ["admin", "engineer", "view-only"]

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="engineer")
    
    # Security fields
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role not in ROLES:
            self.role = "engineer"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        elif self.account_locked_until and self.account_locked_until <= datetime.utcnow():
            # Clear lock if expired
            self.account_locked_until = None
            self.failed_login_attempts = 0
            db.session.commit()
            return False
        return False
    
    def generate_reset_token(self):
        """Generate a password reset token"""
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(seconds=app.config['PASSWORD_RESET_TOKEN_EXPIRY'])
        db.session.commit()
        return self.reset_token
    
    def clear_reset_token(self):
        """Clear reset token after use"""
        self.reset_token = None
        self.reset_token_expiry = None
        db.session.commit()
    
    def record_failed_login(self):
        """Record a failed login attempt"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= app.config['MAX_FAILED_LOGIN_ATTEMPTS']:
            # Lock the account
            self.account_locked_until = datetime.utcnow() + timedelta(
                minutes=app.config['ACCOUNT_LOCKOUT_MINUTES']
            )
            flash(f"Account locked due to too many failed attempts. Try again in {app.config['ACCOUNT_LOCKOUT_MINUTES']} minutes.", "danger")
        db.session.commit()
    
    def reset_failed_logins(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        db.session.commit()

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    documents = db.relationship("Document", backref="project", lazy=True)
    assigned_users = db.relationship(
        "User", secondary=project_user, backref="assigned_projects"
    )


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    versions = db.relationship(
        "DocumentVersion",
        backref="document",
        cascade="all, delete-orphan",
        order_by="DocumentVersion.version_number.desc()"
    )

    tags = db.relationship("Tag", secondary=document_tag, backref="documents")
    author = db.relationship("User")


class DocumentVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"))
    version_number = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_current = db.Column(db.Boolean, default=True)

# ------------------- Utilities -------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                flash("Permission denied.", "danger")
                return redirect(url_for("home"))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ------------------- Dashboard -------------------
@app.route("/")
@login_required
def home():
    projects = Project.query.all() if session["role"] == "admin" \
        else User.query.get(session["user_id"]).assigned_projects
    recent_documents = Document.query.order_by(Document.created_at.desc()).limit(5).all()
    return render_template("dashboard.html", projects=projects, documents=recent_documents)

# ------------------- Auth -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash("Invalid credentials", "danger")
            return render_template("login.html")
        
        # Check if account is locked
        if user.is_account_locked():
            remaining_time = user.account_locked_until - datetime.utcnow()
            minutes = int(remaining_time.total_seconds() // 60)
            flash(f"Account is locked. Try again in {minutes} minutes.", "danger")
            return render_template("login.html")
        
        # Check password
        if user.check_password(password):
            # Successful login
            user.reset_failed_logins()
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            session.update({
                "user_id": user.id,
                "username": user.username,
                "role": user.role,
                "login_time": datetime.utcnow().timestamp()
            })
            
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("home"))
        else:
            # Failed login
            user.record_failed_login()
            
            if user.is_account_locked():
                remaining_time = user.account_locked_until - datetime.utcnow()
                minutes = int(remaining_time.total_seconds() // 60)
                flash(f"Account locked due to too many failed attempts. Try again in {minutes} minutes.", "danger")
            else:
                attempts_left = app.config['MAX_FAILED_LOGIN_ATTEMPTS'] - user.failed_login_attempts
                flash(f"Invalid credentials. {attempts_left} attempts remaining.", "danger")
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))

# ------------------- Password Reset -------------------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    """Forgot password - generates reset token (for development, shows token on screen)"""
    if request.method == "POST":
        username = request.form.get("username")
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Generate reset token
            token = user.generate_reset_token()
            
            # In development: Show token on screen
            # In production: This would be emailed to the user
            flash(f"Password reset token generated: {token}", "info")
            flash(f"Use this token within 1 hour to reset your password.", "info")
            flash(f"Go to: {url_for('reset_password', token=token, _external=True)}", "info")
            
            return redirect(url_for("reset_password", token=token))
        else:
            flash("Username not found.", "danger")
    
    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Reset password using token"""
    user = User.query.filter_by(reset_token=token).first()
    
    if not user:
        flash("Invalid or expired reset token.", "danger")
        return redirect(url_for("forgot_password"))
    
    if user.reset_token_expiry < datetime.utcnow():
        user.clear_reset_token()
        db.session.commit()
        flash("Reset token has expired.", "danger")
        return redirect(url_for("forgot_password"))
    
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
        elif len(new_password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        else:
            # Update password
            user.set_password(new_password)
            user.clear_reset_token()
            user.reset_failed_logins()  # Also reset failed attempts
            db.session.commit()
            
            flash("Password has been reset successfully. You can now login with your new password.", "success")
            return redirect(url_for("login"))
    
    return render_template("reset_password.html", token=token)

# ------------------- Profile Management -------------------
@app.route("/profile")
@login_required
def profile():
    user = User.query.get(session["user_id"])
    return render_template("profile.html", user=user)

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        user.username = request.form.get("username", user.username)
        db.session.commit()
        
        # Update session if username changed
        if session.get("username") != user.username:
            session["username"] = user.username
        
        flash("Profile updated", "success")
        return redirect(url_for("profile"))
    return render_template("edit_profile.html", user=user)

@app.route("/profile/password", methods=["GET", "POST"])
@login_required
def edit_password():
    if request.method == "POST":
        user = User.query.get(session["user_id"])
        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("confirm_password")
        
        if not user.check_password(current):
            flash("Current password is incorrect", "danger")
        elif new != confirm:
            flash("New passwords do not match", "danger")
        elif len(new) < 6:
            flash("Password must be at least 6 characters", "danger")
        else:
            user.set_password(new)
            user.reset_failed_logins()  # Reset failed attempts on password change
            db.session.commit()
            flash("Password updated successfully", "success")
            return redirect(url_for("profile"))
    
    return render_template("edit_password.html")

# ------------------- Admin: User Security Management -------------------
@app.route("/admin/user_security/<int:user_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def user_security(user_id):
    """Admin: View and manage user security settings"""
    user = User.query.get_or_404(user_id)
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "unlock_account":
            user.account_locked_until = None
            user.failed_login_attempts = 0
            db.session.commit()
            flash(f"Account for {user.username} has been unlocked.", "success")
        
        elif action == "reset_password":
            # Generate a temporary password
            temp_password = secrets.token_urlsafe(8)
            user.set_password(temp_password)
            user.reset_failed_logins()
            db.session.commit()
            flash(f"Password reset for {user.username}. Temporary password: {temp_password}", "warning")
        
        elif action == "clear_reset_token":
            user.clear_reset_token()
            db.session.commit()
            flash(f"Reset token cleared for {user.username}.", "success")
    
    return render_template("user_security.html", user=user)

# ------------------- Documents -------------------
@app.route("/documents", methods=["GET", "POST"])
@login_required
def documents():
    if request.method == "POST":
        file = request.files.get("file")
        filename = None

        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Invalid file type", "danger")
                return redirect(url_for("documents"))
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        # Get project_id from form (can be empty)
        project_id = request.form.get("project_id")
        if project_id:
            project_id = int(project_id)
        else:
            project_id = None

        doc = Document(
            title=request.form["title"],
            description=request.form["description"],
            author_id=session["user_id"],
            project_id=project_id  # LINK DOCUMENT TO PROJECT
        )
        db.session.add(doc)
        db.session.commit()

        if filename:
            db.session.add(DocumentVersion(
                document_id=doc.id,
                version_number=1,
                filename=filename,
                is_current=True
            ))
            db.session.commit()

        flash("Document created", "success")
        return redirect(url_for("documents"))

    # GET: Show all documents AND projects for dropdown
    docs = Document.query.order_by(Document.created_at.desc()).all()
    projects = Project.query.all()  # GET ALL PROJECTS FOR DROPDOWN
    return render_template("documents.html", documents=docs, projects=projects)

@app.route("/documents/<int:doc_id>")
@login_required
def document_detail(doc_id):
    """View document details"""
    doc = Document.query.get_or_404(doc_id)
    return render_template("document_detail.html", doc=doc)

@app.route("/documents/<int:doc_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "engineer")
def edit_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if request.method == "POST":
        doc.title = request.form["title"]
        doc.description = request.form["description"]
        
        # Update project assignment if provided
        project_id = request.form.get("project_id")
        if project_id:
            doc.project_id = int(project_id)
        else:
            doc.project_id = None
            
        db.session.commit()
        flash("Document updated", "success")
        return redirect(url_for("documents"))
    
    # GET: Show edit form with all projects
    projects = Project.query.all()
    return render_template("edit_document.html", doc=doc, projects=projects)

@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
@role_required("admin", "engineer")
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    for version in doc.versions:
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], version.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(version)
    db.session.delete(doc)
    db.session.commit()
    flash("Document deleted successfully", "success")
    return redirect(url_for("documents"))

# ------------------- Document Versions -------------------
@app.route("/documents/<int:doc_id>/new-version", methods=["GET", "POST"])
@login_required
@role_required("admin", "engineer")
def upload_new_version(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            flash("No file selected", "danger")
            return redirect(url_for("document_detail", doc_id=doc_id))
        
        if not allowed_file(file.filename):
            flash("Invalid file type", "danger")
            return redirect(url_for("document_detail", doc_id=doc_id))
        
        # Mark old versions as not current
        for version in doc.versions:
            version.is_current = False
        
        # Create new version
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        
        # Calculate next version number
        if doc.versions:
            new_version_number = max([v.version_number for v in doc.versions]) + 1
        else:
            new_version_number = 1
        
        new_version = DocumentVersion(
            document_id=doc.id,
            version_number=new_version_number,
            filename=filename,
            is_current=True
        )
        db.session.add(new_version)
        db.session.commit()
        
        flash(f"New version v{new_version_number} uploaded successfully", "success")
        return redirect(url_for("document_detail", doc_id=doc_id))
    
    return render_template("new_version.html", doc=doc)

# File download route
@app.route("/download/<filename>")
@login_required
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# ------------------- Projects -------------------
@app.route("/projects", methods=["GET", "POST"])
@login_required
def projects():
    """All users can VIEW projects, only admins can CREATE projects"""
    
    # Handle POST: Create new project (ADMIN ONLY)
    if request.method == "POST":
        if session.get("role") != "admin":
            flash("Only administrators can create projects", "danger")
            return redirect(url_for("projects"))
        
        # Admin project creation code
        name = request.form.get("name")
        description = request.form.get("description")
        if not name:
            flash("Project name is required", "danger")
            return redirect(url_for("projects"))
        
        project = Project(name=name, description=description)
        
        # Auto-assign the admin who created the project
        current_user = User.query.get(session["user_id"])
        project.assigned_users.append(current_user)
        
        db.session.add(project)
        db.session.commit()
        flash("Project created successfully", "success")
        return redirect(url_for("projects"))

    # GET: Show projects (different for each role)
    if session.get("role") == "admin":
        # Admins see all projects
        projects = Project.query.all()
    else:
        # Engineers/view-only see only assigned projects
        user = User.query.get(session["user_id"])
        projects = user.assigned_projects if user else []
    
    return render_template("projects.html", projects=projects)

@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    documents = Document.query.filter_by(project_id=project.id).order_by(Document.created_at.desc()).all()
    return render_template("project_detail.html", project=project, documents=documents)

@app.route("/projects/<int:project_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    if request.method == "POST":
        project.name = request.form["name"]
        project.description = request.form["description"]
        db.session.commit()
        flash("Project updated", "success")
        return redirect(url_for("projects"))
    return render_template("edit_project.html", project=project)

@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    flash("Project deleted successfully", "success")
    return redirect(url_for("projects"))

# ------------------- Assign Users to Projects -------------------
@app.route("/projects/<int:project_id>/assign-users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def assign_users_to_project(project_id):
    """Admin: Assign users to a project"""
    project = Project.query.get_or_404(project_id)
    
    if request.method == "POST":
        # Get selected user IDs from form
        user_ids = request.form.getlist("user_ids")
        
        # Clear current assignments
        project.assigned_users = []
        
        # Add selected users
        for user_id in user_ids:
            user = User.query.get(int(user_id))
            if user:
                project.assigned_users.append(user)
        
        db.session.commit()
        flash(f"Users assigned to '{project.name}' successfully", "success")
        return redirect(url_for("project_detail", project_id=project_id))
    
    # GET: Show all users with current assignments checked
    all_users = User.query.all()
    return render_template("assign_users.html", project=project, users=all_users)

# ------------------- Manage Users -------------------
@app.route("/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def manage_users():
    # Handle POST: Create new user
    if request.method == "POST":
        print(f"DEBUG: Creating user - Username: {request.form.get('username')}, Role: {request.form.get('role')}")  # DEBUG
        
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role", "engineer")
        
        # Validation
        if not username or not password:
            flash("Username and password are required", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
        elif len(password) < 6:
            flash("Password must be at least 6 characters", "danger")
        elif role not in ["admin", "engineer", "view-only"]:
            flash("Invalid role selected", "danger")
        else:
            user = User(username=username, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash(f"User '{username}' created successfully as {role}", "success")
            return redirect(url_for("manage_users"))
    
    # GET: Show all users
    users = User.query.all()
    return render_template("users.html", users=users)

# ------------------- Init -------------------
def create_default_admin():
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(debug=True)