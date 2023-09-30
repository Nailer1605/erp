from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SelectField, validators
from urllib.parse import quote
import os
from decouple import Config

# Load environment variables from .env file or from the system environment
config = Config(os.environ)

# Initialize Flask and its extensions
app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configurations
app.config['SECRET_KEY'] = config('SECRET_KEY', default='123123')

# Getting the database credentials from environment
db_user = config('DB_USER', default='root')
db_pass = quote(config('DB_PASS', default='password'))
db_host = config('DB_HOST', default='localhost')
db_name = config('DB_NAME', default='erp_system')

# Constructing the database URI
db_uri = f"mysql+mysqlconnector://{db_user}:{db_pass}@{db_host}/{db_name}"
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Now initialize SQLAlchemy with the app
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)

    @classmethod
    def create_user(cls, username, email, password, role):
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = cls(username=username, email=email, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        return user

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', [validators.InputRequired()])
    password = PasswordField('Password', [validators.InputRequired()])

class SignupForm(FlaskForm):
    username = StringField('Username', [validators.InputRequired()])
    email = StringField('Email', [validators.InputRequired(), validators.Email()])
    password = PasswordField('Password', [validators.InputRequired()])
    role = SelectField('Role', choices=[('customer', 'Customer'), ('supplier', 'Supplier')])

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # TODO: Implement login logic
        return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        User.create_user(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            role=form.role.data
        )
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

# Running the Flask app
if __name__ == "__main__":
    app.run(debug=True)
