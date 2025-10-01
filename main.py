from flask import Flask, render_template, session, redirect, url_for, flash, request, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import or_

from sqlalchemy.orm import backref
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, date
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField, SelectField, DateField
from wtforms.validators import InputRequired, Length, equal_to
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from urllib.parse import urlparse
from dotenv import load_dotenv
import os


# Initialize the Flask application


app = Flask(__name__, template_folder='templates')

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

db_url = os.getenv("DATABASE_URL", "sqlite:///taskmanager.db")

# Render gives DATABASE_URL starting with postgres://, fix it
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Force SSL for Postgres on Render
if db_url.startswith("postgresql") and "sslmode" not in db_url:
    db_url += "?sslmode=require"

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email config (use Gmail or SMTP server)
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "True") == "True"
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

print( 'MAIL_USERNAME' , os.getenv("MAIL_USERNAME"))
print('MAIL_PASSWORD', os.getenv("MAIL_PASSWORD"))

# app.config['MAIL_SERVER'] = 'localhost'
# app.config['MAIL_PORT'] = 8025
# app.config['MAIL_USERNAME'] = None
# app.config['MAIL_PASSWORD'] = None
# app.config['MAIL_USE_TLS'] = False
# app.config['MAIL_USE_SSL'] = False


db = SQLAlchemy(app)
mail = Mail(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # type: ignore

# User and Task Models


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)

    tasks = db.relationship("Task", backref="owner", lazy=True)

    # Generate password reset token
    def get_reset_token(self):
        s = URLSafeTimedSerializer(
            current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    # Verify password reset token
    @staticmethod
    def verify_reset_token(token, max_age=1800):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=max_age)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="Pending")
    date_created = db.Column(db.DateTime,
                             default=lambda: datetime.now(timezone.utc))
    due_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()  # Create database tables


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Using WTF to create forms


class LoginForm(FlaskForm):
    username = StringField('Username: ',
                           validators=[InputRequired(),
                                       Length(min=4, max=20)])
    password = PasswordField('Password: ',
                             validators=[InputRequired(),
                                         Length(min=4, max=20)])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username: ',
                           validators=[InputRequired(),
                                       Length(min=4, max=30)])
    email = EmailField('Email: ',
                       validators=[InputRequired(),
                                   Length(min=4, max=100)])
    password = PasswordField('Password: ',
                             validators=[InputRequired(),
                                         Length(min=4, max=30)])
    submit = SubmitField('Submit')


class TaskForm(FlaskForm):
    title = StringField('Title:',
                        validators=[InputRequired(),
                                    Length(min=4, max=200)])
    description = TextAreaField(
        'Description', validators=[InputRequired(),
                                   Length(min=5, max=500)])
    status = SelectField('Status',
                         choices=[('Pending', 'Pending'),
                                  ('Completed', 'Completed')],
                         default='Pending')
    due_date = DateField('Due Date', default=date.today, format='%Y-%m-%d')
    submit = SubmitField('Add Task')


class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email: ',
                       validators=[InputRequired(),
                                   Length(min=4, max=100)])
    submit = SubmitField('Reset Password')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password: ',
                             validators=[InputRequired(),
                                         Length(min=4, max=30)])
    confirmpassword = PasswordField('Confirm Password: ',
                                    validators=[InputRequired(), equal_to('password', message="Passwords much match")])
    submit = SubmitField('Change Password')

# Routes


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        try:
            if form.validate_on_submit():
                password = form.password.data
                username = form.username.data
                email = form.email.data

                if not password:
                    flash('Password is required', 'warning')
                    return render_template('register.html', form=form)
                existing_user = User.query.filter(
                    or_(User.username == username, User.email == email)).first()
                if existing_user:
                    flash('Username or email already exists', 'warning')
                    return render_template('register.html', form=form)

                hashed_password = generate_password_hash(password,
                                                         method='pbkdf2:sha256',
                                                         salt_length=16)
                new_user = User(username=username,
                                email=email,
                                password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration is successful', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            flash('Username or Email already exists' + str(e))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                flash('Login successful', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('Logout successful', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    form = TaskForm()
    if form.validate_on_submit():
        try:
            title = form.title.data
            description = form.description.data
            status = form.status.data
            due_date = form.due_date.data
            new_task = Task(title=title, description=description,
                            status=status, due_date=due_date, user_id=current_user.id)

            db.session.add(new_task)
            db.session.commit()
            flash('Task added successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding task' + str(e), 'danger')

    tasks = Task.query.filter_by(user_id=current_user.id).order_by(
        Task.date_created.desc()).all()

    return render_template('dashboard.html',
                           form=form,
                           tasks=tasks,
                           username=current_user.username)


@app.route('/update_status')
def update_status():
    today = date.today()
    tasks = Task.query.filter(Task.due_date < today,
                              Task.status != 'Completed').all()
    for task in tasks:
        if task.due_date < today:
            task.status = 'Pending'
        elif task.status == 'Completed':
            task.status = 'Completed'
        else:
            task.status = 'Overdue'
        db.session.commit()
        return redirect(url_for('dashboard'))


@app.route('/taskdetails/<int:task_id>')
def taskdetails(task_id):
    task = Task.query.get_or_404(task_id)
    return render_template('taskdetails.html', task=task)


@app.route('/delete_task/<int:task_id>', methods=['GET', 'POST'])
def delete_task(task_id):
    if request.method == 'POST':
        task = Task.query.get_or_404(task_id)
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully', 'success')
    else:
        flash('Error deleting task', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/edittask/<int:task_id>', methods=['GET', 'POST'])
def edittask(task_id):
    task = Task.query.get_or_404(task_id)
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.status = form.status.data
        task.due_date = form.due_date.data
        db.session.commit()
        flash('Task updated successfully', 'success')
    else:
        flash('Error in updating task', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    form = ForgotPasswordForm()
    if request.method == "POST":
        try:
            email = form.email.data
            user = User.query.filter_by(email=email).first()
            if user:
                token = user.get_reset_token()

            # send email
                msg = Message('Password Reset Request',
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[user.email])
                msg.body = f"Click the link to reset your password: {url_for('reset_token', token=token, _external=True)}"
                mail.send(msg)
                flash("Check your email for the reset link", "info")
            else:
                flash("No account found with that email.", "warning")

            return redirect(url_for('login'))
        except Exception as e:
            import traceback
            print("Error in forgotpassword:", str(e))
            traceback.print_exc()  # full error trace in console/logs
            # show the actual error for debugging
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for("forgotpassword"))

    return render_template('forgotpassword.html', form=form)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    form = ResetPasswordForm()
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgotpassword'))

    if request.method == "POST":
        new_password = form.password.data
        hashed_pw = generate_password_hash(new_password)
        user = User.query.filter_by(email=email).first()
        user.password = hashed_pw
        db.session.commit()
        flash('Your password has been updated! You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('resetpassword.html', token=token, form=form)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
