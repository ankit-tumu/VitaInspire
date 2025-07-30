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
from config import Config
from models import User
from extensions import db

# --- App and Database Configuration ---
load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config.from_object(Config)

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

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize database tables
with app.app_context():
    db.create_all()


# --- Database Model ---
# (Moved to models.py)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- HTML Templates (Registration and Dashboard Updated) ---
# --- Inline Templates ---
# (Moved to templates/ directory)


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
        - Exercise Time Available: {getattr(user, 'exercise_time', 30)} minutes
        - Current Cravings: {user.common_foods}

        **User's Real-Time Context:**
        - Recent Activity (from Strava): {strava_summary}
        - Current Weather: {weather_summary}

        **Your Task:**
        1.  **Analyze & Reason:** In a "Coach's Note", briefly explain your reasoning for today's plan. Explicitly mention how the weather, recent Strava activity, and gym access influenced your decision.
        2.  **Create the Plan:**
            - **Workout:** Design a {getattr(user, 'exercise_time', 30)}-minute workout. If the user has gym access, include exercises using common gym equipment (e.g., dumbbells, barbells). If not, provide a bodyweight or home-based workout. Adjust the number and duration of exercises to fit within the {getattr(user, 'exercise_time', 30)}-minute timeframe.
            - **Nutrition:** Incorporate the user's current cravings into the meal suggestions while keeping them aligned with their fitness goal. Suggest healthier alternatives or ways to satisfy cravings in moderation.
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

    # Save to Google Drive (optional - plan generation continues even if this fails)
    print("TOOL: 📄 Saving plan to Google Drive...")
    try:
        if user.google_token:
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
        else:
            print("TOOL: ⚠️ Google Drive not connected - plan saved locally only.")
    except Exception as e:
        print(f"An error occurred with Google Drive: {e}")
        print("TOOL: ⚠️ Plan generation continues without Google Drive save.")
    
    return plan_dict


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
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # Redirect logged-in users to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
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

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if existing_user.is_verified:
                flash('Email address already registered and verified. Please login.', 'info')
                return redirect(url_for('login'))
            else:
                flash('Email address already registered but not verified. Please check your email for verification link.', 'warning')
                return redirect(url_for('login'))
        
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
    return render_template('register.html')


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
    # Redirect logged-in users to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Email address not found. Please register first.', 'danger')
            return redirect(url_for('login'))
        
        if not user.check_password(password):
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        if not user.is_verified:
            flash('Please verify your email address before logging in. Check your email for the verification link.', 'warning')
            return redirect(url_for('login'))

        session.pop('current_plan', None)
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    plan = session.get('current_plan')
    if plan:
        plan['workout_activity_html'] = markdown2.markdown(plan['workout_activity'])
        plan['meal_suggestion_html'] = markdown2.markdown(plan['meal_suggestion'])
    return render_template('dashboard.html', plan=plan, now=datetime.now())


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
    # Temporarily handle exercise_time field that might not exist yet
    try:
        current_user.exercise_time = int(request.form.get('exercise_time', 30))
    except AttributeError:
        # If the field doesn't exist yet, just skip it for now
        pass
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
    # Use environment variables instead of credentials file
    client_config = {
        "web": {
            "client_id": os.getenv('GOOGLE_CLIENT_ID'),
            "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [url_for('google_callback', _external=True)]
        }
    }
    
    flow = Flow.from_client_config(client_config, scopes=GOOGLE_SCOPES,
                                   redirect_uri=url_for('google_callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['google_oauth_state'] = state
    return redirect(authorization_url)


@app.route('/google-callback')
@login_required
def google_callback():
    state = session.pop('google_oauth_state', None)
    
    # Use environment variables instead of credentials file
    client_config = {
        "web": {
            "client_id": os.getenv('GOOGLE_CLIENT_ID'),
            "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [url_for('google_callback', _external=True)]
        }
    }
    
    flow = Flow.from_client_config(client_config, scopes=GOOGLE_SCOPES, state=state,
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


if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(os.path.join(basedir, 'instance')):
            os.makedirs(os.path.join(basedir, 'instance'))
        db.create_all()
    app.run(debug=True)
