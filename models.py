from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db

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
    common_foods = db.Column(db.Text)  # Stores user cravings/preferences
    has_gym_access = db.Column(db.Boolean, default=False)
    exercise_time = db.Column(db.Integer, default=30)  # Exercise time in minutes

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)