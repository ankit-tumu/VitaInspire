# app.py - Your main Flask application file

from flask import Flask, render_template, request, redirect, url_for, flash, render_template_string, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import json
from dotenv import load_dotenv
import io
import base64
from email.message import EmailMessage
from datetime import datetime, timedelta
import smtplib
import requests

# --- API Imports ---
from itsdangerous import URLSafeTimedSerializer
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
import google.generativeai as genai
import pandas as pd
from stravalib.client import Client
import markdown2

# --- App and Database Configuration ---
load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'a_super_secret_key_change_this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Email Server Configuration ---
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# --- API Configuration ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
GOOGLE_CREDENTIALS_PATH = os.path.join(basedir, 'credentials.json')
# --- CORRECTED GOOGLE SCOPES ---
GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events",
    "openid"
]
STRAVA_CLIENT_ID = os.getenv('STRAVA_CLIENT_ID')
STRAVA_CLIENT_SECRET = os.getenv('STRAVA_CLIENT_SECRET')
WEATHER_API_KEY = os.getenv('WEATHER_API_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# --- Database Model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    google_token = db.Column(db.Text)
    strava_token = db.Column(db.Text)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    height = db.Column(db.String(20))
    weight = db.Column(db.Integer)
    fitness_goal = db.Column(db.Text)
    zip_code = db.Column(db.String(10))
    # New personalization fields
    common_foods = db.Column(db.Text)
    has_gym_access = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- HTML Templates (Registration and Dashboard Updated) ---
base_template = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Vita Inspire</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('home') }}">🤖 Vita Inspire</a>
        <div class="d-flex">
          {% if current_user.is_authenticated %}
            <a href="{{ url_for('dashboard') }}" class="btn btn-outline-light me-2">Dashboard</a>
            <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
          {% else %}
            <a href="{{ url_for('login') }}" class="btn btn-outline-light me-2">Login</a>
            <a href="{{ url_for('register') }}" class="btn btn-primary">Sign-Up</a>
          {% endif %}
        </div>
      </div>
    </nav>
    <div class="container mt-4">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{ category }}">{{ message }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      {% block content %}{% endblock %}
    </div>
  </body>
</html>
"""
home_template = """
{% extends "base.html" %}
{% block content %}
  <div class="p-5 mb-4 bg-light rounded-3">
    <div class="container-fluid py-5">
      <h1 class="display-5 fw-bold">Welcome to Vita Inspire</h1>
      <p class="col-md-8 fs-4">Your AI-powered personal fitness and nutrition coach. Sign up or log in to get started.</p>
    </div>
  </div>
{% endblock %}
"""
register_template = """
{% extends "base.html" %}
{% block content %}
  <h2>Register a New Account</h2>
  <form method="POST" action="">
    <div class="mb-3">
      <label for="email" class="form-label">Email address</label>
      <input type="email" class="form-control" name="email" required>
    </div>
    <div class="mb-3">
      <label for="password" class="form-label">Password</label>
      <input type="password" class="form-control" name="password" required>
    </div>
    <div class="mb-3">
      <label for="password2" class="form-label">Confirm Password</label>
      <input type="password" class="form-control" name="password2" required>
    </div>
    <hr>
    <h5>Your Details</h5>
    <div class="mb-3">
      <label for="height" class="form-label">Height</label>
      <input type="text" class="form-control" name="height" placeholder="e.g., 5ft 10in" required>
    </div>
    <div class="mb-3">
      <label for="weight" class="form-label">Weight (lbs)</label>
      <input type="number" class="form-control" name="weight" placeholder="e.g., 180" required>
    </div>
    <div class="mb-3">
      <label for="zip_code" class="form-label">Zip Code</label>
      <input type="text" class="form-control" name="zip_code" required>
    </div>
    <div class="mb-3">
        <label class="form-label">Primary Fitness Goal</label>
        <div class="input-group">
            <select class="form-select" name="goal_type">
                <option value="Lose Weight">Lose Weight</option>
                <option value="Run a Distance">Run a Distance</option>
                <option value="Bench Press">Bench Press</option>
            </select>
            <input type="number" class="form-control" name="goal_value" placeholder="Value" min="1" required>
            <select class="form-select" name="goal_unit">
                <option value="lbs">lbs</option>
                <option value="kg">kg</option>
                <option value="miles">miles</option>
                <option value="km">km</option>
            </select>
        </div>
    </div>
    <button type="submit" class="btn btn-primary">Register</button>
  </form>
{% endblock %}
"""
login_template = """
{% extends "base.html" %}
{% block content %}
  <h2>Login to Your Account</h2>
  <form method="POST" action="">
    <div class="mb-3">
      <label for="email" class="form-label">Email address</label>
      <input type="email" class="form-control" name="email" required>
    </div>
    <div class="mb-3">
      <label for="password" class="form-label">Password</label>
      <input type="password" class="form-control" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
  </form>
{% endblock %}
"""
dashboard_template = """
{% extends "base.html" %}
{% block content %}
  <h3>Welcome, {{ current_user.email }}!</h3>

  <div class="row">
    <div class="col-md-5">
        <h4>Connect & Configure</h4>
        <div class="card mb-4">
            <div class="card-body">
                <p><strong>Google:</strong> 
                    {% if current_user.google_token %}<span class="badge bg-success">Connected</span>{% else %}<a href="{{ url_for('connect_google') }}" class="btn btn-sm btn-danger">Connect</a>{% endif %}
                </p>
                <p><strong>Strava:</strong> 
                    {% if current_user.strava_token %}<span class="badge bg-success">Connected</span>{% else %}<a href="{{ url_for('connect_strava') }}" class="btn btn-sm btn-warning">Connect</a>{% endif %}
                </p>
            </div>
        </div>
        <div class="card">
            <div class="card-body">
                <h5>Generate Your Daily Plan</h5>
                <p>Your goal is currently set to: <strong>{{ current_user.fitness_goal }}</strong></p>
                {% if current_user.google_token and current_user.strava_token %}
                <form id="generate-plan-form" method="POST" action="{{ url_for('generate_plan') }}">
                    <div class="mb-3">
                        <label for="common_foods" class="form-label">Common Foods You Eat</label>
                        <textarea class="form-control" name="common_foods" rows="3" placeholder="e.g., chicken breast, rice, broccoli, eggs...">{{ current_user.common_foods or '' }}</textarea>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" class="form-check-input" name="has_gym_access" value="true" {% if current_user.has_gym_access %}checked{% endif %}>
                        <label class="form-check-label" for="has_gym_access">I have access to a gym</label>
                    </div>
                    <button type="submit" id="generate-plan-btn" class="btn btn-primary w-100">
                        <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
                        <span class="button-text">Generate Today's Plan</span>
                    </button>
                </form>
                {% else %}
                <p class="text-muted">Please connect both accounts to generate a plan.</p>
                {% endif %}
            </div>
        </div>
    </div>
    <div class="col-md-7">
        <h4>Your Generated Plan</h4>
        {% if plan %}
        <div class="card">
            <div class="card-header">
                Plan for {{ now.strftime('%A, %B %d') }}
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <strong>Coach's Note:</strong> {{ plan.coach_note }}
                </div>
                <h5>Workout</h5>
                <div class="plan-content">{{ plan.workout_activity_html | safe }}</div>
                <p><strong>Target:</strong> Burn {{ plan.calories_to_burn }} calories</p>
                <hr>
                <h5>Nutrition</h5>
                <div class="plan-content">{{ plan.meal_suggestion_html | safe }}</div>
                <p><strong>Target:</strong> Consume {{ plan.calories_to_consume }} calories</p>
            </div>
            <div class="card-footer text-end">
                <form method="POST" action="{{ url_for('add_to_calendar') }}" style="display: inline;">
                    <button type="submit" class="btn btn-info">Add to Calendar</button>
                </form>
                <form method="POST" action="{{ url_for('send_email') }}" style="display: inline;">
                    <button type="submit" class="btn btn-success">Send to Email</button>
                </form>
            </div>
        </div>
        {% else %}
        <div class="card">
            <div class="card-body text-center text-muted">
                <p>Your plan will appear here once you generate it.</p>
            </div>
        </div>
        {% endif %}
    </div>
  </div>

  <script>
    const form = document.getElementById('generate-plan-form');
    if (form) {
      form.addEventListener('submit', function() {
        const btn = document.getElementById('generate-plan-btn');
        const spinner = btn.querySelector('.spinner-border');
        const buttonText = btn.querySelector('.button-text');

        btn.disabled = true;
        spinner.classList.remove('d-none');
        buttonText.textContent = ' Generating...';
      });
    }
  </script>
{% endblock %}
"""


# --- Helper Function for Sending Emails ---
def send_verification_email(user_email):
    token = s.dumps(user_email, salt='email-confirm-salt')
    verification_url = url_for('verify_email', token=token, _external=True)
    msg = EmailMessage()
    msg.set_content(f'Welcome to Vita Inspire! Please click the link to verify your email address: {verification_url}')
    msg['Subject'] = 'Confirm Your Email Address'
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = user_email
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


# --- Agent Logic & Tool Functions ---

def get_google_creds_from_user(user):
    """Recreates a Google Credentials object from the user's token."""
    token_dict = json.loads(user.google_token)
    return Credentials(**token_dict)


def fetch_strava_data_for_user(user):
    """Fetches the user's recent Strava activity."""
    print("TOOL: 🏃 Fetching Strava data...")
    if not user.strava_token:
        return None
    try:
        token_dict = json.loads(user.strava_token)
        client = Client(access_token=token_dict['access_token'])

        activities = client.get_activities(limit=5)
        summary = "Recent activities:\n"
        for activity in activities:
            summary += f"- {activity.name} ({activity.distance.num / 1000:.2f} km)\n"
        return summary
    except Exception as e:
        print(f"An error occurred with Strava: {e}")
        return "Could not retrieve Strava data."


def get_weather_for_user(zip_code):
    """Fetches the current weather for the user's location."""
    print(f"TOOL: 🌦️ Fetching weather for zipcode {zip_code}...")
    url = f"https://api.openweathermap.org/data/2.5/weather?zip={zip_code},us&appid={WEATHER_API_KEY}&units=imperial"
    try:
        response = requests.get(url).json()
        condition = response['weather'][0]['main']
        temp_f = round(response['main']['temp'])
        return f"Current weather is {condition} with a temperature of {temp_f}°F."
    except Exception as e:
        print(f"An error occurred with Weather API: {e}")
        return "Weather data is currently unavailable."


def generate_plan_for_user(user, strava_summary, weather_summary):
    """Generates a deeply personalized fitness plan."""
    print("TOOL: 🧠 Generating deeply personalized plan with Google Gemini...")
    try:
        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        prompt = f"""
        You are Vita, an elite AI fitness coach. Create a concise, scannable, and actionable daily plan for {user.email.split('@')[0]}.

        **User's Core Data:**
        - Height: {user.height}
        - Weight: {user.weight} lbs
        - Goal: {user.fitness_goal}
        - Gym Access: {'Yes' if user.has_gym_access else 'No'}
        - Common Foods: {user.common_foods}

        **User's Real-Time Context:**
        - Recent Activity (from Strava): {strava_summary}
        - Current Weather: {weather_summary}

        **Your Task:**
        1.  **Analyze & Reason:** In a "Coach's Note", briefly explain your reasoning for today's plan. Explicitly mention how the weather, recent Strava activity, and gym access influenced your decision.
        2.  **Create the Plan:**
            - **Workout:** If the user has gym access, include exercises using common gym equipment (e.g., dumbbells, barbells). If not, provide a bodyweight or home-based workout.
            - **Nutrition:** Incorporate some of the user's "Common Foods" into the meal suggestions if they align with the fitness goal.
        3.  **Format:** Use markdown bullet points (*) for all exercises and meal items. Keep descriptions brief.

        Respond with ONLY a valid JSON object in the following format:
        {{"coach_note": "Your reasoning here...", "workout_activity": "* Warm-up: ...\\n* Main Set: ...", "calories_to_burn": 500, "meal_suggestion": "* Breakfast: ...\\n* Lunch: ...", "calories_to_consume": 1800}}
        """
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)

        cleaned_text = response.text.strip().replace("```json", "").replace("```", "").strip()
        plan_dict = json.loads(cleaned_text)
        print("TOOL: ✅ AI-generated plan.")
    except Exception as e:
        print(f"An error occurred with the AI model: {e}")
        return None

    # Save to Google Drive
    print("TOOL: 📄 Saving plan to Google Drive...")
    try:
        creds = get_google_creds_from_user(user)
        service = build("drive", "v3", credentials=creds)
        file_name = f"{user.email.replace('@', '_').replace('.', '_')}.xlsx"
        df = pd.DataFrame([{"Date": pd.Timestamp.now().strftime('%Y-%m-%d'), **plan_dict}])

        buffer = io.BytesIO()
        df.to_excel(buffer, index=False, sheet_name='Plan')
        buffer.seek(0)

        file_metadata = {'name': file_name}
        media = MediaIoBaseUpload(buffer, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

        response = service.files().list(q=f"name='{file_name}' and trashed=false", fields='files(id)').execute()
        if response.get('files'):
            file_id = response.get('files')[0].get('id')
            service.files().update(fileId=file_id, media_body=media).execute()
        else:
            service.files().create(body=file_metadata, media_body=media, fields='id').execute()

        print(f"TOOL: ✅ Saved plan to '{file_name}'.")
        return plan_dict
    except Exception as e:
        print(f"An error occurred with Google Drive: {e}")
        return None


def send_email_for_user(user, plan):
    """Sends the generated plan to the user's email."""
    print("TOOL: 📧 Sending summary email...")
    try:
        creds = get_google_creds_from_user(user)
        service = build("gmail", "v1", credentials=creds)

        workout_html = markdown2.markdown(plan['workout_activity'])
        nutrition_html = markdown2.markdown(plan['meal_suggestion'])

        email_body = f"""
        <html>
        <body>
            <h3>Good morning {user.email.split('@')[0]},</h3>
            <p>Here is your Vita Inspire plan for today:</p>
            <div style="background-color:#f0f8ff; padding: 15px; border-radius: 8px;">
                <strong>Coach's Note:</strong> {plan.get('coach_note', 'Have a great workout!')}
            </div>
            <hr>
            <h4>Workout</h4>
            {workout_html}
            <p><strong>Target:</strong> Burn {plan['calories_to_burn']} calories</p>
            <hr>
            <h4>Nutrition</h4>
            {nutrition_html}
            <p><strong>Target:</strong> Consume {plan['calories_to_consume']} calories</p>
        </body>
        </html>
        """
        message = EmailMessage()
        message.set_content("Please view this email in an HTML-compatible client.")
        message.add_alternative(email_body, subtype='html')

        message["To"] = user.email
        message["From"] = user.email
        message["Subject"] = f"Your Vita Inspire Plan for {datetime.now().strftime('%B %d')}"
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        service.users().messages().send(userId="me", body={"raw": encoded_message}).execute()
        print("TOOL: ✅ Email sent.")
        return True
    except Exception as e:
        print(f"An error occurred sending email: {e}")
        return False


def create_calendar_event_for_user(user, plan):
    """Creates a calendar event for the user's workout."""
    print("TOOL: 🗓️ Creating calendar event...")
    try:
        creds = get_google_creds_from_user(user)
        service = build("calendar", "v3", credentials=creds)

        plain_text_description = f"Coach's Note: {plan.get('coach_note', '')}\n\n" + re.sub(r'<[^>]+>', '',
                                                                                            markdown2.markdown(plan[
                                                                                                                   'workout_activity']))

        today_date = datetime.now().date()
        start_time = datetime.combine(today_date, datetime.min.time()) + timedelta(hours=8)
        end_time = start_time + timedelta(hours=1)
        event = {
            'summary': f"Vita Inspire Workout",
            'description': plain_text_description,
            'start': {'dateTime': start_time.isoformat(), 'timeZone': 'America/New_York'},
            'end': {'dateTime': end_time.isoformat(), 'timeZone': 'America/New_York'},
        }
        service.events().insert(calendarId='primary', body=event).execute()
        print("TOOL: ✅ Calendar event created.")
        return True
    except Exception as e:
        print(f"An error occurred creating calendar event: {e}")
        return False


# --- Routes (Authentication and Core App) ---

@app.route('/')
def home():
    session.pop('current_plan', None)
    return render_template_with_base(home_template)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        height = request.form.get('height')
        weight = request.form.get('weight')
        zip_code = request.form.get('zip_code')
        goal_type = request.form.get('goal_type')
        goal_value = request.form.get('goal_value')
        goal_unit = request.form.get('goal_unit')
        fitness_goal = f"{goal_type} {goal_value} {goal_unit}"

        if User.query.filter_by(email=email).first():
            flash('Email address already exists.', 'warning');
            return redirect(url_for('register'))
        if password != password2:
            flash('Passwords do not match.', 'danger');
            return redirect(url_for('register'))
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(
                r'\d', password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('Password does not meet security requirements.', 'danger');
            return redirect(url_for('register'))

        new_user = User(email=email, height=height, weight=int(weight), zip_code=zip_code, fitness_goal=fitness_goal)
        new_user.set_password(password)

        if send_verification_email(email):
            db.session.add(new_user);
            db.session.commit()
            flash('Thanks for registering! A verification email has been sent.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Could not send verification email.', 'danger')
    return render_template_with_base(register_template)


@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger');
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_verified:
        flash('Account already verified.', 'success')
    else:
        user.is_verified = True;
        db.session.commit()
        flash('You have successfully verified your account!', 'success')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password) or not user.is_verified:
            flash('Please check your login details and try again.', 'danger');
            return redirect(url_for('login'))

        session.pop('current_plan', None)

        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template_with_base(login_template)


@app.route('/dashboard')
@login_required
def dashboard():
    plan = session.get('current_plan')
    if plan:
        plan['workout_activity_html'] = markdown2.markdown(plan['workout_activity'])
        plan['meal_suggestion_html'] = markdown2.markdown(plan['meal_suggestion'])
    return render_template_with_base(dashboard_template, plan=plan, now=datetime.now())


@app.route('/logout')
@login_required
def logout():
    logout_user();
    session.pop('current_plan', None)
    return redirect(url_for('home'))


# --- UPDATED Agent Route ---
@app.route('/generate-plan', methods=['POST'])
@login_required
def generate_plan():
    # 1. Save new preferences from the form
    current_user.common_foods = request.form.get('common_foods')
    current_user.has_gym_access = request.form.get('has_gym_access') == 'true'
    db.session.commit()

    # 2. Gather all real-time context
    strava_summary = fetch_strava_data_for_user(current_user)
    weather_summary = get_weather_for_user(current_user.zip_code)

    # 3. Generate the plan using all available data
    plan = generate_plan_for_user(current_user, strava_summary, weather_summary)

    if plan:
        session['current_plan'] = plan
        flash('Your deeply personalized plan has been generated!', 'success')
    else:
        flash('There was an error generating your plan.', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/send-email', methods=['POST'])
@login_required
def send_email():
    plan = session.get('current_plan')
    if not plan:
        flash('No plan found to send. Please generate one first.', 'warning')
        return redirect(url_for('dashboard'))

    if send_email_for_user(current_user, plan):
        flash('Your plan has been sent to your email!', 'success')
    else:
        flash('There was an error sending the email.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/add-to-calendar', methods=['POST'])
@login_required
def add_to_calendar():
    plan = session.get('current_plan')
    if not plan:
        flash('No plan found to schedule. Please generate one first.', 'warning')
        return redirect(url_for('dashboard'))

    if create_calendar_event_for_user(current_user, plan):
        flash('Your workout has been added to your Google Calendar!', 'success')
    else:
        flash('There was an error adding the event to your calendar.', 'danger')
    return redirect(url_for('dashboard'))


# --- OAuth Routes ---
@app.route('/connect-google')
@login_required
def connect_google():
    flow = Flow.from_client_secrets_file(GOOGLE_CREDENTIALS_PATH, scopes=GOOGLE_SCOPES,
                                         redirect_uri=url_for('google_callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['google_oauth_state'] = state
    return redirect(authorization_url)


@app.route('/google-callback')
@login_required
def google_callback():
    state = session.pop('google_oauth_state', None)
    flow = Flow.from_client_secrets_file(GOOGLE_CREDENTIALS_PATH, scopes=GOOGLE_SCOPES, state=state,
                                         redirect_uri=url_for('google_callback', _external=True))
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    current_user.google_token = json.dumps(
        {'token': credentials.token, 'refresh_token': credentials.refresh_token, 'token_uri': credentials.token_uri,
         'client_id': credentials.client_id, 'client_secret': credentials.client_secret, 'scopes': credentials.scopes})
    db.session.commit()
    flash('Successfully connected your Google account!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/connect-strava')
@login_required
def connect_strava():
    client = Client()
    authorize_url = client.authorization_url(client_id=STRAVA_CLIENT_ID,
                                             redirect_uri=url_for('strava_callback', _external=True),
                                             scope=['read', 'activity:read'])
    return redirect(authorize_url)


@app.route('/strava-callback')
@login_required
def strava_callback():
    code = request.args.get('code')
    if code:
        client = Client()
        token_response = client.exchange_code_for_token(client_id=STRAVA_CLIENT_ID, client_secret=STRAVA_CLIENT_SECRET,
                                                        code=code)
        current_user.strava_token = json.dumps(token_response)
        db.session.commit()
        flash('Successfully connected your Strava account!', 'success')
    else:
        flash('Could not connect to Strava.', 'danger')
    return redirect(url_for('dashboard'))


# --- Helper Function for Rendering ---
def render_template_with_base(template_string, **context):
    content_block = template_string.replace('{% extends "base.html" %}', '')
    full_html = base_template.replace('{% block content %}{% endblock %}', content_block)
    return render_template_string(full_html, **context)


if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(os.path.join(basedir, 'instance')):
            os.makedirs(os.path.join(basedir, 'instance'))
        db.create_all()
    app.run(debug=True)
