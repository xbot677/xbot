import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

# --- APP INITIALIZATION AND CONFIGURATION (Unchanged) ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-key-change-this' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db) 

# --- FLASK-LOGIN CONFIGURATION (Unchanged) ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DATABASE MODELS (Unchanged) ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    groups = db.relationship('ManagedGroup', backref='owner', lazy=True)

class ManagedGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_chat_id = db.Column(db.String(100), unique=True, nullable=False)
    bot_token = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    spam_keywords = db.relationship('SpamKeyword', backref='group', lazy=True, cascade="all, delete-orphan")
    allowed_usernames = db.relationship('AllowedUsername', backref='group', lazy=True, cascade="all, delete-orphan")
    allowed_domains = db.relationship('AllowedDomain', backref='group', lazy=True, cascade="all, delete-orphan")
    authorized_users = db.relationship('AuthorizedUser', backref='group', lazy=True, cascade="all, delete-orphan")

class SpamKeyword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    keyword = db.Column(db.String(100), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('managed_group.id'), nullable=False)
    
class AllowedUsername(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('managed_group.id'), nullable=False)

class AllowedDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(100), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('managed_group.id'), nullable=False)

class AuthorizedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('managed_group.id'), nullable=False)

# --- WEB ROUTES (Most are unchanged) ---
@app.route('/')
def index():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))
        new_user = User(username=username, password_hash=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    groups = ManagedGroup.query.filter_by(owner=current_user).all()
    return render_template('dashboard.html', groups=groups)

@app.route('/add_group', methods=['POST'])
@login_required
def add_group():
    chat_id = request.form.get('chat_id')
    bot_token = request.form.get('bot_token')
    existing_group = ManagedGroup.query.filter_by(telegram_chat_id=chat_id).first()
    if existing_group:
        flash('This Group Chat ID is already being managed.')
        return redirect(url_for('dashboard'))
    new_group = ManagedGroup(telegram_chat_id=chat_id, bot_token=bot_token, owner=current_user)
    db.session.add(new_group)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/group/<int:group_id>/delete')
@login_required
def delete_group(group_id):
    group = ManagedGroup.query.get_or_404(group_id)
    if group.owner != current_user: return "Unauthorized", 403
    db.session.delete(group)
    db.session.commit()
    return redirect(url_for('dashboard'))

# Keyword Management Routes (Unchanged)
@app.route('/group/<int:group_id>/add_keyword', methods=['POST'])
@login_required
def add_keyword(group_id):
    group = ManagedGroup.query.get_or_404(group_id)
    if group.owner != current_user: return "Unauthorized", 403
    new_keyword = SpamKeyword(keyword=request.form.get('keyword'), group=group)
    db.session.add(new_keyword)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/keyword/<int:keyword_id>/delete')
@login_required
def delete_keyword(keyword_id):
    keyword = SpamKeyword.query.get_or_404(keyword_id)
    if keyword.group.owner != current_user: return "Unauthorized", 403
    db.session.delete(keyword)
    db.session.commit()
    return redirect(url_for('dashboard'))

# Username Management Routes (Unchanged)
@app.route('/group/<int:group_id>/add_username', methods=['POST'])
@login_required
def add_username(group_id):
    group = ManagedGroup.query.get_or_404(group_id)
    if group.owner != current_user: return "Unauthorized", 403
    new_username = AllowedUsername(username=request.form.get('username'), group=group)
    db.session.add(new_username)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/username/<int:username_id>/delete')
@login_required
def delete_username(username_id):
    username = AllowedUsername.query.get_or_404(username_id)
    if username.group.owner != current_user: return "Unauthorized", 403
    db.session.delete(username)
    db.session.commit()
    return redirect(url_for('dashboard'))

# Domain Management Routes (Unchanged)
@app.route('/group/<int:group_id>/add_domain', methods=['POST'])
@login_required
def add_domain(group_id):
    group = ManagedGroup.query.get_or_404(group_id)
    if group.owner != current_user: return "Unauthorized", 403
    new_domain = AllowedDomain(domain=request.form.get('domain'), group=group)
    db.session.add(new_domain)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/domain/<int:domain_id>/delete')
@login_required
def delete_domain(domain_id):
    domain = AllowedDomain.query.get_or_404(domain_id)
    if domain.group.owner != current_user: return "Unauthorized", 403
    db.session.delete(domain)
    db.session.commit()
    return redirect(url_for('dashboard'))

# Authorized User Management Routes (Unchanged)
@app.route('/group/<int:group_id>/add_authorized_user', methods=['POST'])
@login_required
def add_authorized_user(group_id):
    group = ManagedGroup.query.get_or_404(group_id)
    if group.owner != current_user: return "Unauthorized", 403
    new_user = AuthorizedUser(user_id=request.form.get('user_id'), group=group)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/authorized_user/<int:user_id>/delete')
@login_required
def delete_authorized_user(user_id):
    user = AuthorizedUser.query.get_or_404(user_id)
    if user.group.owner != current_user: return "Unauthorized", 403
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('dashboard'))

# --- NEW ROUTE FOR EXPORTING SETTINGS ---
@app.route('/group/<int:source_group_id>/export', methods=['POST'])
@login_required
def export_settings(source_group_id):
    source_group = ManagedGroup.query.get_or_404(source_group_id)
    if source_group.owner != current_user:
        return "Unauthorized", 403

    action = request.form.get('action')
    target_groups = []

    if action == 'copy_selected':
        target_group_ids = request.form.getlist('target_groups')
        if not target_group_ids:
            flash('You did not select any groups to export to.')
            return redirect(url_for('dashboard'))
        target_groups = ManagedGroup.query.filter(ManagedGroup.id.in_(target_group_ids), ManagedGroup.owner == current_user).all()

    elif action == 'copy_all':
        target_groups = ManagedGroup.query.filter(ManagedGroup.owner == current_user, ManagedGroup.id != source_group_id).all()

    else:
        flash('Invalid action.')
        return redirect(url_for('dashboard'))

    if not target_groups:
        flash('No valid target groups found to export to.')
        return redirect(url_for('dashboard'))

    # Helper function to perform the copy
    def copy_rules(source, destination):
        # Clear existing rules from the destination group first
        destination.spam_keywords.clear()
        destination.allowed_usernames.clear()
        destination.allowed_domains.clear()
        destination.authorized_users.clear()
        
        # Copy new rules from the source group
        for item in source.spam_keywords:
            destination.spam_keywords.append(SpamKeyword(keyword=item.keyword))
        for item in source.allowed_usernames:
            destination.allowed_usernames.append(AllowedUsername(username=item.username))
        for item in source.allowed_domains:
            destination.allowed_domains.append(AllowedDomain(domain=item.domain))
        for item in source.authorized_users:
            destination.authorized_users.append(AuthorizedUser(user_id=item.user_id))

    for target_group in target_groups:
        copy_rules(source_group, target_group)

    db.session.commit()
    flash(f"Settings from {source_group.telegram_chat_id} were successfully copied to {len(target_groups)} group(s).")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)