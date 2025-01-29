from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, abort
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
import os
import hashlib
import MySQLdb  
from dotenv import load_dotenv
import secrets

# For raw SQL to create the database if it doesn't exist

# Flask app initialization
app = Flask(__name__)


# Create the serializer for token generation
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Create upload folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER'])
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Secret key for session and token generation

# Generate the secret key
secret_key = secrets.token_hex(16)

# Print the key to verify it
print(f"Generated Secret Key: {secret_key}")

# Now, set this secret key in Flask
app.config['SECRET_KEY'] = secret_key  # Store this in app.config
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123456789@localhost/secure_file_sharing'  # Change according to your DB settings
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize MySQL and SQLAlchemy
db = SQLAlchemy(app)

# Function to create the database if it doesn't exist
def create_database():
    try:
        # Connect to MySQL server (without specifying a database)
        conn = MySQLdb.connect(user='root', password='password')  # Adjust as per your MySQL credentials
        cursor = conn.cursor()

        # Create the database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS secure_file_sharing")
        conn.commit()
        cursor.close()
        conn.close()
        print("Database 'secure_file_sharing' is ready.")
    except Exception as e:
        print(f"Error creating database: {e}")

# Database Model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.String(10), nullable=False)  # 'user1' for admin, 'user2' for general user

# Function to create users
def create_user(username, password, user_type):
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, user_type=user_type)
    db.session.add(new_user)
    db.session.commit()
    print(f"User {username} added successfully")

# Initialize DB tables and create users
with app.app_context():
    db.create_all()  # Create tables if they don't exist

    # Check if users already exist before creating them
    if not User.query.filter_by(username='ops_user').first():
        create_user('admin_user', 'adminpassword123', 'ops_user')

    if not User.query.filter_by(username='client_user').first():
        create_user('general_user', 'userpassword123', 'client_user')

    print("Users created successfully.")


# Helper function to generate secure URL token
def generate_secure_url(filename):
    return serializer.dumps(filename, salt='file-download-salt')

# Helper function to verify the secure URL token
def verify_secure_url(token, max_age=3600):
    try:
        filename = serializer.loads(token, salt='file-download-salt', max_age=max_age)
        return filename
    except Exception:
        return None
        
# Helper function to check if user is authenticated and is of the correct user type
def is_user_authenticated(required_user_type):
    # Check if user is logged in and if their user type matches
    if 'user_id' not in session:
        return False
    user = User.query.get(session['user_id'])
    if user and user.user_type == required_user_type:
        return True
    return False

# Routes

@app.route('/')
def home():
    return render_template('index.html')

# User 1 (Admin) login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        user = User.query.filter_by(username=username, password=password, user_type='user1').first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('user1_dashboard'))
        else:
            return 'Invalid credentials', 403
    return render_template('ops_user_login_page.html')

# User 2 (General user) login
@app.route('/user2/login', methods=['GET', 'POST'])
def user2_login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        user = User.query.filter_by(username=username, password=password, user_type='user2').first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('user2_dashboard'))
        else:
            return 'Invalid credentials', 403
    return render_template('client_user_login_page.html')

# User 1 dashboard (File upload page)
@app.route('/user1/dashboard', methods=['GET', 'POST'])
def user1_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith(('.pptx', '.docx', '.xlsx')):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Generate a secure URL for the uploaded file
            secure_url = generate_secure_url(filename)
            return f'File uploaded successfully! Download URL: <a href="/download/{secure_url}">Download</a>'
        else:
            return 'Invalid file format. Only pptx, docx, and xlsx files are allowed.', 400

    return render_template('ops_user_dashboard.html')

# User 2 dashboard (View and download files)
@app.route('/user2/dashboard')
def user2_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('user2_login'))

    # List of uploaded files available for download
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('client_user_dashboard.html', files=files)

# Download file with secure token
@app.route('/download/<token>', methods=['GET'])
def download_file(token):
    filename = verify_secure_url(token)
    if filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
        else:
            abort(404)  # File not found
    else:
        abort(403)  # Invalid or expired token

# Signup for User 2 (General User)
@app.route('/user2/signup', methods=['GET', 'POST'])
def user2_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'Username already taken', 400

        new_user = User(username=username, password=password, user_type='user2')
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('user2_login'))

    return render_template('client_user_signup.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)
