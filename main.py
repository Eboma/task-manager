from flask import Flask, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash



#Initialize the Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///taskmanager.db'
app.config['SECRET_KEY'] = '12301!@ebome#tunde%%123'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # type: ignore




@app.route('/')
def index():
  return 'Hello World!!'




if __name__ == '__main__':
   app.run(host='0.0.0.0', port=5000, debug=True)