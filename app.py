import os
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_from_directory, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
import secrets
import time
import hashlib
from pathlib import Path

# ------------------- App Setup -------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Security settings
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session timeout: 2 hours
app.config['MAX_FAILED_LOGIN_ATTEMPTS'] = 5  # Lock after 5 failed attempts
app.config['ACCOUNT_LOCKOUT_MINUTES'] = 15   # Lock for 15 minutes
app.config['PASSWORD_RESET_TOKEN_EXPIRY'] = 3600  # 1 hour in seconds

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt", "md", 
    "xls", "xlsx", "ppt", "pptx", "jpg", 
    "jpeg", "png", "zip", "csv", "json", "xml"
}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///documents.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ------------------- Constants -------------------
ROLES = ["admin", "engineer", "view-only"]
DOCUMENT_CATEGORIES = [
    "General", "Technical", "Design", "Requirements", 
    "API Documentation", "User Manual", "Test Cases",
    "Architecture", "Meeting Notes", "Proposals"
]
DOCUMENT_STATUSES = ["draft", "in_review", "approved", "archived"]

# =========== ADD KNOWLEDGE BASE CONSTANTS ===========
KNOWLEDGE_BASE_TYPES = [
    "coding_guidelines",
    "system_architecture", 
    "deployment_notes",
    "best_practices",
    "security_standards",
    "code_review_guide",
    "testing_standards",
    "documentation_standards"
]

KNOWLEDGE_BASE_CATEGORIES = [
    "Development",
    "DevOps",
    "Security",
    "Quality Assurance",
    "Project Management",
    "Team Processes"
]
# =========== END KNOWLEDGE BASE CONSTANTS ===========

# ------------------- Context Processor -------------------
@app.context_processor
def inject_now():
    return {
        "now": datetime.utcnow(),
        "DOCUMENT_CATEGORIES": DOCUMENT_CATEGORIES,
        "DOCUMENT_STATUSES": DOCUMENT_STATUSES,
        # =========== ADD KNOWLEDGE BASE CONSTANTS ===========
        "KNOWLEDGE_BASE_TYPES": KNOWLEDGE_BASE_TYPES,
        "KNOWLEDGE_BASE_CATEGORIES": KNOWLEDGE_BASE_CATEGORIES
        # =========== END ADDITIONS ===========
    }

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
    # TEMPORARILY COMMENTED OUT - Add these back after database update
    # is_archived = db.Column(db.Boolean, default=False)
    # created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    documents = db.relationship("Document", backref="project", lazy=True)
    assigned_users = db.relationship(
        "User", secondary=project_user, backref="assigned_projects"
    )


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


class Comment(db.Model):
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='comments')
    document = db.relationship('Document', backref='comments')

    def can_edit(self, user):
        """Check if user can edit this comment"""
        return user.id == self.user_id or user.role == 'admin'
    
    def can_delete(self, user):
        """Check if user can delete this comment"""
        return (user.id == self.user_id or 
                user.id == self.document.author_id or 
                user.role == 'admin')


class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(500))  # URL to relevant page
    is_read = db.Column(db.Boolean, default=False)
    notification_type = db.Column(db.String(50))  # 'comment', 'mention', 'status_change', 'assignment'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='notifications')
    
    @property
    def time_ago(self):
        """Return human-readable time since notification"""
        now = datetime.utcnow()
        diff = now - self.created_at
        
        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds >= 3600:
            hours = diff.seconds // 3600
            return f"{hours}h ago"
        elif diff.seconds >= 60:
            minutes = diff.seconds // 60
            return f"{minutes}m ago"
        else:
            return "Just now"


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    category = db.Column(db.String(50), default="General")
    status = db.Column(db.String(20), default="draft")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # =========== ADD KNOWLEDGE BASE FIELDS ===========
    is_knowledge_base = db.Column(db.Boolean, default=False)
    knowledge_type = db.Column(db.String(50), nullable=True)
    knowledge_category = db.Column(db.String(50), nullable=True)
    # =========== END KNOWLEDGE BASE FIELDS ===========

    versions = db.relationship(
        "DocumentVersion",
        backref="document",
        cascade="all, delete-orphan",
        order_by="DocumentVersion.version_number.desc()"
    )

    tags = db.relationship("Tag", secondary=document_tag, backref="documents")
    author = db.relationship("User")
    
    @property
    def latest_version(self):
        """Get the latest version of this document"""
        return self.versions[0] if self.versions else None
    
    @property
    def file_extension(self):
        """Get file extension from latest version"""
        if self.latest_version:
            return os.path.splitext(self.latest_version.filename)[1].lower()
        return ""
    
    # =========== ADD KNOWLEDGE BASE PROPERTY ===========
    @property
    def formatted_knowledge_type(self):
        """Return formatted knowledge type for display"""
        if self.knowledge_type:
            return self.knowledge_type.replace('_', ' ').title()
        return ""
    # =========== END KNOWLEDGE BASE PROPERTY ===========


class DocumentVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"))
    version_number = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(20))
    checksum = db.Column(db.String(64))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    change_description = db.Column(db.Text)
    is_current = db.Column(db.Boolean, default=True)
    previous_version_id = db.Column(db.Integer, db.ForeignKey("document_version.id"))
    
    uploader = db.relationship("User")
    previous_version = db.relationship("DocumentVersion", remote_side=[id])
    
    @property
    def formatted_size(self):
        """Return human-readable file size"""
        if not self.file_size:
            return "Unknown"
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

# ------------------- Utilities -------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_file_checksum(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_metadata(filepath):
    file_size = os.path.getsize(filepath)
    extension = Path(filepath).suffix.lower()[1:] if Path(filepath).suffix else ""
    
    extension_to_type = {
        'pdf': 'PDF Document',
        'doc': 'Word Document',
        'docx': 'Word Document',
        'txt': 'Text File',
        'md': 'Markdown File',
        'xls': 'Excel Spreadsheet',
        'xlsx': 'Excel Spreadsheet',
        'ppt': 'PowerPoint Presentation',
        'pptx': 'PowerPoint Presentation',
        'jpg': 'Image',
        'jpeg': 'Image',
        'png': 'Image',
        'zip': 'Archive',
        'csv': 'CSV File',
        'json': 'JSON File',
        'xml': 'XML File'
    }
    
    file_type = extension_to_type.get(extension, 'Unknown')
    
    return {
        'size': file_size,
        'extension': extension,
        'type': file_type
    }

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

# ------------------- Notification Utilities -------------------
def create_notification(user_id, title, message, link=None, notification_type=None):
    """Create a new notification for a user"""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        link=link,
        notification_type=notification_type,
        is_read=False
    )
    db.session.add(notification)
    db.session.commit()
    return notification

def notify_comment(document, commenter):
    """Notify document author about new comment"""
    if document.author_id != commenter.id:
        create_notification(
            user_id=document.author_id,
            title="New Comment on Your Document",
            message=f"{commenter.username} commented on '{document.title}'",
            link=f"/documents/{document.id}",
            notification_type='comment'
        )

def notify_document_status_change(document, changer, old_status, new_status):
    """Notify document author about status change"""
    if document.author_id != changer.id:
        create_notification(
            user_id=document.author_id,
            title="Document Status Updated",
            message=f"{changer.username} changed status of '{document.title}' from {old_status} to {new_status}",
            link=f"/documents/{document.id}",
            notification_type='status_change'
        )

def notify_project_assignment(user, project, assigner):
    """Notify user about project assignment"""
    create_notification(
        user_id=user.id,
        title="Added to Project",
        message=f"{assigner.username} added you to project '{project.name}'",
        link=f"/projects/{project.id}",
        notification_type='assignment'
    )

def get_unread_notification_count(user_id):
    """Get count of unread notifications for a user"""
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()

def get_recent_notifications(user_id, limit=10):
    """Get recent notifications for a user"""
    return Notification.query.filter_by(user_id=user_id)\
                           .order_by(Notification.created_at.desc())\
                           .limit(limit)\
                           .all()

# ------------------- Dashboard -------------------
@app.route("/")
@login_required
def home():
    # Get projects for dashboard
    if session["role"] == "admin":
        projects = Project.query.limit(5).all()
    else:
        user = User.query.get(session["user_id"])
        projects = user.assigned_projects[:5] if user else []
    
    recent_documents = Document.query.order_by(Document.created_at.desc()).limit(5).all()
    
    # =========== ADD KNOWLEDGE BASE TO DASHBOARD ===========
    # Get recent knowledge base articles
    recent_knowledge = Document.query.filter_by(is_knowledge_base=True)\
                                   .order_by(Document.updated_at.desc())\
                                   .limit(5).all()
    # =========== END ADDITION ===========
    
    return render_template("dashboard.html", 
                         projects=projects, 
                         documents=recent_documents,
                         recent_knowledge=recent_knowledge)  # =========== ADD THIS ===========

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
        
        if user.is_account_locked():
            remaining_time = user.account_locked_until - datetime.utcnow()
            minutes = int(remaining_time.total_seconds() // 60)
            flash(f"Account is locked. Try again in {minutes} minutes.", "danger")
            return render_template("login.html")
        
        if user.check_password(password):
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
    if request.method == "POST":
        username = request.form.get("username")
        user = User.query.filter_by(username=username).first()
        
        if user:
            token = user.generate_reset_token()
            flash(f"Password reset token generated: {token}", "info")
            flash(f"Use this token within 1 hour to reset your password.", "info")
            flash(f"Go to: {url_for('reset_password', token=token, _external=True)}", "info")
            return redirect(url_for("reset_password", token=token))
        else:
            flash("Username not found.", "danger")
    
    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
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
            user.set_password(new_password)
            user.clear_reset_token()
            user.reset_failed_logins()
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
            user.reset_failed_logins()
            db.session.commit()
            flash("Password updated successfully", "success")
            return redirect(url_for("profile"))
    
    return render_template("edit_password.html")

# ------------------- Admin: User Security Management -------------------
@app.route("/admin/user_security/<int:user_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def user_security(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "unlock_account":
            user.account_locked_until = None
            user.failed_login_attempts = 0
            db.session.commit()
            flash(f"Account for {user.username} has been unlocked.", "success")
        elif action == "reset_password":
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
        file_metadata = None

        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Invalid file type", "danger")
                return redirect(url_for("documents"))
            
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)
            file_metadata = get_file_metadata(file_path)

        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "General")
        project_id = request.form.get("project_id")
        
        if not title:
            flash("Document title is required", "danger")
            return redirect(url_for("documents"))
        
        if project_id:
            project_id = int(project_id)
        else:
            project_id = None

        doc = Document(
            title=title,
            description=description,
            author_id=session["user_id"],
            project_id=project_id,
            category=category,
            status="draft"
        )
        db.session.add(doc)
        db.session.commit()

        if filename and file_metadata:
            version = DocumentVersion(
                document_id=doc.id,
                version_number=1,
                filename=filename,
                file_size=file_metadata['size'],
                file_type=file_metadata['type'],
                checksum=calculate_file_checksum(file_path),
                uploaded_by=session["user_id"],
                change_description="Initial version",
                is_current=True
            )
            db.session.add(version)
            db.session.commit()
            flash(f"Document '{title}' created with version 1", "success")
        else:
            flash(f"Document '{title}' created (no file uploaded)", "success")
        
        return redirect(url_for("documents"))

    # =========== GET REQUEST - HANDLE SEARCH AND FILTERS ===========
    # Get search query from URL parameters
    search_query = request.args.get("q", "").strip()
    
    # Get filter parameters
    project_filter = request.args.get("project", "")
    author_filter = request.args.get("author", "")
    category_filter = request.args.get("category", "")
    status_filter = request.args.get("status", "")
    date_filter = request.args.get("date", "")
    
    # Start with base query
    query = Document.query
    
    # Apply search query if provided
    if search_query:
        query = query.filter(
            db.or_(
                Document.title.ilike(f"%{search_query}%"),
                Document.description.ilike(f"%{search_query}%")
            )
        )
    
    # Apply project filter
    if project_filter:
        query = query.filter(Document.project_id == project_filter)
    
    # Apply author filter
    if author_filter:
        query = query.filter(Document.author_id == author_filter)
    
    # Apply category filter
    if category_filter:
        query = query.filter(Document.category == category_filter)
    
    # Apply status filter
    if status_filter:
        query = query.filter(Document.status == status_filter)
    
    # Apply date filter
    if date_filter:
        if date_filter == "today":
            today = datetime.utcnow().date()
            query = query.filter(db.func.date(Document.created_at) == today)
        elif date_filter == "week":
            week_ago = datetime.utcnow() - timedelta(days=7)
            query = query.filter(Document.created_at >= week_ago)
        elif date_filter == "month":
            month_ago = datetime.utcnow() - timedelta(days=30)
            query = query.filter(Document.created_at >= month_ago)
        elif date_filter == "year":
            year_ago = datetime.utcnow() - timedelta(days=365)
            query = query.filter(Document.created_at >= year_ago)
    
    # Get filtered documents
    docs = query.order_by(Document.created_at.desc()).all()
    
    # Get data for filters
    projects = Project.query.all()
    users = User.query.all()
    
    return render_template("documents.html", 
                         documents=docs, 
                         projects=projects, 
                         users=users,
                         tags=Tag.query.all(),
                         categories=DOCUMENT_CATEGORIES,
                         search_query=search_query,
                         current_project_filter=project_filter,
                         current_author_filter=author_filter,
                         current_category_filter=category_filter,
                         current_status_filter=status_filter,
                         current_date_filter=date_filter)

@app.route("/documents/<int:doc_id>")
@login_required
def document_detail(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    # Get comments for this document, ordered by newest first
    comments = Comment.query.filter_by(document_id=doc_id)\
                           .order_by(Comment.created_at.desc())\
                           .all()
    
    return render_template("document_detail.html", doc=doc, comments=comments)

@app.route("/documents/<int:doc_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "engineer")
def edit_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    if request.method == "POST":
        old_status = doc.status
        
        # Update basic fields
        doc.title = request.form["title"]
        doc.description = request.form["description"]
        doc.category = request.form.get("category", "General")
        doc.status = request.form.get("status", "draft")
        
        # =========== ADD KNOWLEDGE BASE FIELDS ===========
        doc.is_knowledge_base = request.form.get("is_knowledge_base") == "on"
        doc.knowledge_type = request.form.get("knowledge_type") or None
        doc.knowledge_category = request.form.get("knowledge_category") or None
        # =========== END KNOWLEDGE BASE FIELDS ===========
        
        # Handle tags
        tag_names = request.form.get("tags", "").strip()
        if tag_names:
            tag_list = [tag.strip() for tag in tag_names.split(",") if tag.strip()]
            # Clear existing tags
            doc.tags = []
            for tag_name in tag_list:
                # Find or create tag
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                doc.tags.append(tag)
        else:
            doc.tags = []
        
        project_id = request.form.get("project_id")
        if project_id:
            doc.project_id = int(project_id)
        else:
            doc.project_id = None
            
        db.session.commit()
        
        # Notify about status change if status changed
        if old_status != doc.status:
            changer = User.query.get(session['user_id'])
            notify_document_status_change(doc, changer, old_status, doc.status)
        
        flash("Document updated successfully", "success")
        return redirect(url_for("document_detail", doc_id=doc.id))
    
    projects = Project.query.all()
    all_tags = Tag.query.all()
    current_tag_names = ",".join([tag.name for tag in doc.tags])
    return render_template("edit_document.html", 
                         doc=doc, 
                         projects=projects, 
                         all_tags=all_tags,
                         current_tag_names=current_tag_names)

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
        change_description = request.form.get("change_description", "").strip()
        
        if not file or not file.filename:
            flash("No file selected", "danger")
            return redirect(url_for("document_detail", doc_id=doc_id))
        
        if not allowed_file(file.filename):
            flash("Invalid file type", "danger")
            return redirect(url_for("document_detail", doc_id=doc_id))
        
        previous_version = doc.versions[0] if doc.versions else None
        
        for version in doc.versions:
            version.is_current = False
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)
        file_metadata = get_file_metadata(file_path)
        
        if doc.versions:
            new_version_number = max([v.version_number for v in doc.versions]) + 1
        else:
            new_version_number = 1
        
        new_version = DocumentVersion(
            document_id=doc.id,
            version_number=new_version_number,
            filename=filename,
            file_size=file_metadata['size'],
            file_type=file_metadata['type'],
            checksum=calculate_file_checksum(file_path),
            uploaded_by=session["user_id"],
            change_description=change_description or f"Version {new_version_number} uploaded",
            is_current=True,
            previous_version_id=previous_version.id if previous_version else None
        )
        db.session.add(new_version)
        doc.updated_at = datetime.utcnow()
        db.session.commit()
        
        flash(f"New version v{new_version_number} uploaded successfully", "success")
        return redirect(url_for("document_detail", doc_id=doc_id))
    
    return render_template("new_version.html", doc=doc)

@app.route("/documents/version/<int:version_id>/rollback", methods=["POST"])
@login_required
@role_required("admin", "engineer")
def rollback_version(version_id):
    version_to_rollback = DocumentVersion.query.get_or_404(version_id)
    doc = version_to_rollback.document
    
    if version_to_rollback.is_current:
        flash("This version is already the current version", "warning")
        return redirect(url_for("document_detail", doc_id=doc.id))
    
    for version in doc.versions:
        version.is_current = False
    
    version_to_rollback.is_current = True
    new_version_number = max([v.version_number for v in doc.versions]) + 1
    
    new_version = DocumentVersion(
        document_id=doc.id,
        version_number=new_version_number,
        filename=version_to_rollback.filename,
        file_size=version_to_rollback.file_size,
        file_type=version_to_rollback.file_type,
        checksum=version_to_rollback.checksum,
        uploaded_by=session["user_id"],
        change_description=f"Rolled back to version {version_to_rollback.version_number}",
        is_current=True,
        previous_version_id=version_to_rollback.id
    )
    db.session.add(new_version)
    doc.updated_at = datetime.utcnow()
    db.session.commit()
    
    flash(f"Successfully rolled back to version {version_to_rollback.version_number}", "success")
    return redirect(url_for("document_detail", doc_id=doc.id))

@app.route("/documents/<int:doc_id>/versions")
@login_required
def document_versions(doc_id):
    doc = Document.query.get_or_404(doc_id)
    return render_template("document_versions.html", doc=doc)

# ------------------- Comments -------------------
@app.route("/document/<int:doc_id>/comment", methods=["POST"])
@login_required
def add_comment(doc_id):
    """Add a comment to a document"""
    doc = Document.query.get_or_404(doc_id)
    
    content = request.form.get('content', '').strip()
    
    if not content:
        flash("Comment cannot be empty.", "error")
        return redirect(url_for('document_detail', doc_id=doc_id))
    
    # Create comment
    comment = Comment(
        content=content,
        user_id=session['user_id'],
        document_id=doc_id
    )
    
    db.session.add(comment)
    db.session.commit()
    
    # Notify document author about new comment
    commenter = User.query.get(session['user_id'])
    notify_comment(doc, commenter)
    
    flash("Comment added successfully!", "success")
    return redirect(url_for('document_detail', doc_id=doc_id))

@app.route("/comment/<int:comment_id>/edit", methods=["POST"])
@login_required
def edit_comment(comment_id):
    """Edit a comment"""
    comment = Comment.query.get_or_404(comment_id)
    
    # Check permission
    user = User.query.get(session['user_id'])
    if not comment.can_edit(user):
        flash("You can only edit your own comments.", "error")
        return redirect(url_for('document_detail', doc_id=comment.document_id))
    
    content = request.form.get('content', '').strip()
    
    if not content:
        flash("Comment cannot be empty.", "error")
        return redirect(url_for('document_detail', doc_id=comment.document_id))
    
    comment.content = content
    comment.updated_at = datetime.utcnow()
    db.session.commit()
    
    flash("Comment updated successfully!", "success")
    return redirect(url_for('document_detail', doc_id=comment.document_id))

@app.route("/comment/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    """Delete a comment"""
    comment = Comment.query.get_or_404(comment_id)
    document_id = comment.document_id
    
    # Check permission
    user = User.query.get(session['user_id'])
    if not comment.can_delete(user):
        flash("You don't have permission to delete this comment.", "error")
        return redirect(url_for('document_detail', doc_id=document_id))
    
    db.session.delete(comment)
    db.session.commit()
    
    flash("Comment deleted successfully!", "success")
    return redirect(url_for('document_detail', doc_id=document_id))

# ------------------- Tags Management -------------------
@app.route("/tags")
@login_required
def tags():
    """View and manage all tags"""
    all_tags = Tag.query.order_by(Tag.name).all()
    
    # Get tag statistics
    tag_stats = []
    for tag in all_tags:
        tag_stats.append({
            'tag': tag,
            'document_count': len(tag.documents)
        })
    
    return render_template("tags.html", tag_stats=tag_stats)

@app.route("/tags/<int:tag_id>/rename", methods=["POST"])
@login_required
@role_required("admin", "engineer")
def rename_tag(tag_id):
    """Rename a tag"""
    tag = Tag.query.get_or_404(tag_id)
    new_name = request.form.get('new_name', '').strip()
    
    if not new_name:
        flash("Tag name cannot be empty.", "error")
        return redirect(url_for('tags'))
    
    # Check if tag with new name already exists
    existing_tag = Tag.query.filter_by(name=new_name).first()
    if existing_tag and existing_tag.id != tag_id:
        flash(f"Tag '{new_name}' already exists.", "error")
        return redirect(url_for('tags'))
    
    old_name = tag.name
    tag.name = new_name
    db.session.commit()
    
    flash(f"Tag renamed from '{old_name}' to '{new_name}'.", "success")
    return redirect(url_for('tags'))

@app.route("/tags/<int:tag_id>/delete", methods=["POST"])
@login_required
@role_required("admin", "engineer")
def delete_tag(tag_id):
    """Delete a tag (only if not in use)"""
    tag = Tag.query.get_or_404(tag_id)
    
    if tag.documents:
        flash(f"Cannot delete tag '{tag.name}' because it's used by {len(tag.documents)} documents.", "error")
        return redirect(url_for('tags'))
    
    db.session.delete(tag)
    db.session.commit()
    
    flash(f"Tag '{tag.name}' deleted successfully.", "success")
    return redirect(url_for('tags'))

@app.route("/documents/tag/<string:tag_name>")
@login_required
def documents_by_tag(tag_name):
    """View all documents with a specific tag"""
    tag = Tag.query.filter_by(name=tag_name).first_or_404()
    documents = tag.documents
    
    return render_template("documents_by_tag.html", 
                         tag=tag, 
                         documents=documents,
                         document_count=len(documents))

# ------------------- Notifications -------------------
@app.route("/notifications")
@login_required
def notifications():
    """View all notifications"""
    user_notifications = Notification.query.filter_by(
        user_id=session['user_id']
    ).order_by(Notification.created_at.desc()).all()
    
    unread_count = get_unread_notification_count(session['user_id'])
    
    return render_template("notifications.html", 
                         notifications=user_notifications,
                         unread_count=unread_count)

@app.route("/notifications/mark_read/<int:notification_id>")
@login_required
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    
    # Security check
    if notification.user_id != session['user_id']:
        flash("Permission denied.", "error")
        return redirect(url_for('notifications'))
    
    notification.is_read = True
    db.session.commit()
    
    # Redirect to link if provided, otherwise back to notifications
    if notification.link:
        return redirect(notification.link)
    else:
        return redirect(url_for('notifications'))

@app.route("/notifications/mark_all_read", methods=["POST"])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    Notification.query.filter_by(
        user_id=session['user_id'],
        is_read=False
    ).update({'is_read': True})
    
    db.session.commit()
    flash("All notifications marked as read.", "success")
    return redirect(url_for('notifications'))

@app.route("/notifications/clear_all", methods=["POST"])
@login_required
def clear_all_notifications():
    """Clear all notifications"""
    Notification.query.filter_by(user_id=session['user_id']).delete()
    db.session.commit()
    flash("All notifications cleared.", "success")
    return redirect(url_for('notifications'))

@app.route("/api/notifications/count")
@login_required
def notification_count():
    """API endpoint to get unread notification count (for AJAX updates)"""
    count = get_unread_notification_count(session['user_id'])
    return jsonify({'count': count})

@app.route("/api/notifications/recent")
@login_required
def recent_notifications():
    """API endpoint to get recent notifications (for AJAX updates)"""
    notifications = get_recent_notifications(session['user_id'], limit=5)
    notifications_data = []
    
    for notification in notifications:
        notifications_data.append({
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'link': notification.link,
            'is_read': notification.is_read,
            'time_ago': notification.time_ago,
            'type': notification.notification_type
        })
    
    return jsonify({'notifications': notifications_data})

# File download route
@app.route("/download/<filename>")
@login_required
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

@app.route("/preview/<filename>")
@login_required
def preview_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ------------------- Projects -------------------
@app.route("/projects", methods=["GET", "POST"])
@login_required
def projects():
    if request.method == "POST":
        if session.get("role") != "admin":
            flash("Only administrators can create projects", "danger")
            return redirect(url_for("projects"))
        
        name = request.form.get("name")
        description = request.form.get("description")
        if not name:
            flash("Project name is required", "danger")
            return redirect(url_for("projects"))
        
        project = Project(name=name, description=description)
        current_user = User.query.get(session["user_id"])
        project.assigned_users.append(current_user)
        db.session.add(project)
        db.session.commit()
        flash("Project created successfully", "success")
        return redirect(url_for("projects"))

    if session.get("role") == "admin":
        projects = Project.query.all()
    else:
        user = User.query.get(session["user_id"])
        projects = user.assigned_projects if user else []
    
    return render_template("projects.html", projects=projects, show_archived='false')

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
    project = Project.query.get_or_404(project_id)
    
    if request.method == "POST":
        user_ids = request.form.getlist("user_ids")
        assigner = User.query.get(session['user_id'])
        
        # Get previous users to identify new assignments
        previous_users = set(project.assigned_users)
        project.assigned_users = []
        
        for user_id in user_ids:
            user = User.query.get(int(user_id))
            if user:
                project.assigned_users.append(user)
                # Notify newly assigned users
                if user not in previous_users:
                    notify_project_assignment(user, project, assigner)
        
        db.session.commit()
        flash(f"Users assigned to '{project.name}' successfully", "success")
        return redirect(url_for("project_detail", project_id=project_id))
    
    all_users = User.query.all()
    return render_template("assign_users.html", project=project, users=all_users)

# ------------------- Manage Users -------------------
@app.route("/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def manage_users():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role", "engineer")
        
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
    
    users = User.query.all()
    return render_template("users.html", users=users)

# ------------------- Search -------------------
@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "").strip()
    
    # If no query, redirect to documents page
    if not query:
        return redirect(url_for("documents"))
    
    # Search in documents
    documents_results = Document.query.filter(
        db.or_(
            Document.title.ilike(f"%{query}%"),
            Document.description.ilike(f"%{query}%")
        )
    ).order_by(Document.updated_at.desc()).all()
    
    # Search in comments
    comments_results = Comment.query.filter(
        Comment.content.ilike(f"%{query}%")
    ).order_by(Comment.created_at.desc()).all()
    
    # Search in projects
    projects_results = Project.query.filter(
        db.or_(
            Project.name.ilike(f"%{query}%"),
            Project.description.ilike(f"%{query}%")
        )
    ).all()
    
    # Get category filter if present
    category = request.args.get("category", "")
    project_id = request.args.get("project_id", "")
    
    return render_template("search.html", 
                         documents_results=documents_results,
                         comments_results=comments_results,
                         projects_results=projects_results,
                         query=query,
                         category=category,
                         project_id=project_id,
                         projects=Project.query.all(),
                         categories=DOCUMENT_CATEGORIES)

# =========== KNOWLEDGE BASE ROUTES ===========
@app.route("/knowledge-base")
@login_required
def knowledge_base():
    """Knowledge Base homepage"""
    # Get all knowledge base documents
    kb_docs = Document.query.filter_by(is_knowledge_base=True)\
                           .order_by(Document.updated_at.desc())\
                           .all()
    
    # Group by knowledge category
    docs_by_category = {}
    for doc in kb_docs:
        category = doc.knowledge_category or "Uncategorized"
        if category not in docs_by_category:
            docs_by_category[category] = []
        docs_by_category[category].append(doc)
    
    # Get statistics
    total_kb_docs = len(kb_docs)
    categories_count = len(docs_by_category)
    
    # Get most recent updates
    recent_updates = kb_docs[:5] if kb_docs else []
    
    return render_template("knowledge_base.html",
                         kb_docs=kb_docs,
                         docs_by_category=docs_by_category,
                         total_kb_docs=total_kb_docs,
                         categories_count=categories_count,
                         recent_updates=recent_updates)

@app.route("/knowledge-base/<knowledge_type>")
@login_required
def knowledge_base_type(knowledge_type):
    """View documents by knowledge type"""
    if knowledge_type not in KNOWLEDGE_BASE_TYPES:
        flash("Invalid knowledge type", "danger")
        return redirect(url_for("knowledge_base"))
    
    docs = Document.query.filter_by(
        is_knowledge_base=True,
        knowledge_type=knowledge_type
    ).order_by(Document.title).all()
    
    formatted_type = knowledge_type.replace('_', ' ').title()
    
    return render_template("knowledge_type.html",
                         docs=docs,
                         knowledge_type=knowledge_type,
                         formatted_type=formatted_type)

@app.route("/knowledge-base/category/<category_name>")
@login_required
def knowledge_base_category(category_name):
    """View documents by knowledge category"""
    docs = Document.query.filter_by(
        is_knowledge_base=True,
        knowledge_category=category_name
    ).order_by(Document.title).all()
    
    return render_template("knowledge_category.html",
                         docs=docs,
                         category_name=category_name)

@app.route("/documents/<int:doc_id>/toggle-knowledge-base", methods=["POST"])
@login_required
@role_required("admin", "engineer")
def toggle_knowledge_base(doc_id):
    """Toggle document as knowledge base item"""
    doc = Document.query.get_or_404(doc_id)
    
    doc.is_knowledge_base = not doc.is_knowledge_base
    
    if doc.is_knowledge_base and not doc.knowledge_type:
        # Set default knowledge type if none set
        doc.knowledge_type = "best_practices"
    
    db.session.commit()
    
    action = "added to" if doc.is_knowledge_base else "removed from"
    flash(f"Document '{doc.title}' {action} Knowledge Base", "success")
    return redirect(url_for("document_detail", doc_id=doc_id))
# =========== END KNOWLEDGE BASE ROUTES ===========

# ------------------- Init -------------------
def create_default_admin():
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

# ------------------- Database Setup -------------------
def setup_database():
    with app.app_context():
        db.create_all()
        create_default_admin()
        print("Database initialized successfully!")

# ------------------- Main Entry Point -------------------
if __name__ == "__main__":
    setup_database()
    print("Starting Engineering Documentation Portal...")
    print("Access the application at: http://127.0.0.1:5000")
    print("Default admin login: username='admin', password='admin123'")
    print("\nPress Ctrl+C to stop the server")
    app.run(debug=True, host='0.0.0.0', port=5000)