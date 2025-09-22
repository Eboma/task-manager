from enum import unique
from flask import Flask, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import Nullable
from sqlalchemy.orm import backref
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, IntegerField, validators
from wtforms.validators import InputRequired, Length

#Initialize the Flask application
app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///taskmanager.db'
app.config['SECRET_KEY'] = '12301!@ebome#tunde%%123'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # type: ignore

#User and Task Models


class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(100), unique=True, nullable=False)
  email = db.Column(db.String(100), unique=True, nullable=False)
  password = db.Column(db.String(100), nullable=False)

  tasks = db.relationship("Task", backref="owner", lazy=True)


class Task(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String(200), nullable=False)
  description = db.Column(db.String(200), nullable=False)
  status = db.Column(db.String(50), nullable=False, default="Pending")
  date_create = db.Column(db.DateTime,
                          default=lambda: datetime.now(timezone.utc))
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))


#Using WTF to create forms


class LoginForm(FlaskForm):
  username = StringField('Useranme',
                         validators=[InputRequired(),
                                     Length(min=4, max=20)])
  password = PasswordField('Password', validators=[InputRequired()])
  submit = SubmitField('Login')


class RegisterForm(FlaskForm):
  username = StringField('Username: ',
                         validators=[InputRequired(),
                                     Length(min=8, max=20)])
  email = EmailField('Email: ',
                     validators=[InputRequired(),
                                 Length(min=8, max=20)])
  password = PasswordField('Password: ',
                           validators=[InputRequired(),
                                       Length(min=8, max=20)])
  submit = SubmitField('Submit')


#Routes
@app.route('/')
def index():
  return render_template('index.html')


@app.route('/register', methods=['GET','POST'])
def register():
  form = RegisterForm()
  if form.validate_on_submit():

    password = form.password.data
    username = form.username.data
    email = form.email.data
    session['username'] = username
    if password is None:
      flash('Password is required')
      return render_template('register.html', form=form)

    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, email=email, password=hashed_password)




















if __name__ == '__main__':
  with app.app_context():
    db.create_all()  # Create database tables
  app.run(host='0.0.0.0', port=5000, debug=True)
