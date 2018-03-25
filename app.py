from flask import Flask, render_template, redirect, url_for, Session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, FloatField, DateField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
# Configure application
app.config.from_pyfile('config_file.cfg')
app.config.update(dict(
    SECRET_KEY="wedferrstddndhge",
    WTF_CSRF_SECRET_KEY="alex"
))
# Create bootstrap, mail, database and login manager objects
Bootstrap(app)
mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
serializer = URLSafeTimedSerializer('Thisisasecret!')


# Database object for users
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))


# Current user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Web forms
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)],
                           render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=80)],
                             render_kw={"placeholder": "password"})
    remember = BooleanField("Remember me")


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)],
                        render_kw={"placeholder": "email address"})
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)],
                           render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=80)],
                             render_kw={"placeholder": "password"})


class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)],
                        render_kw={"placeholder": "email address"})


class ChangePassword(FlaskForm):
    new_password = PasswordField('New Password',
                                 validators=[InputRequired(), Length(min=8, max=80)],
                                 render_kw={"placeholder": "new password"})
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired(), Length(min=8, max=80)],
                                     render_kw={"placeholder": "confirm password"})


# Routines
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        flash(u'Incorrect username or password!', 'error')
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data,
                                                 method='sha256')
        new_user = User(email=form.email.data, username=form.username.data,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('setup'))
    return render_template('signup.html', form=form)


@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email_address = form.email.data
        token = serializer.dumps(email_address, salt='email-confirm')
        msg = Message('Reset Password', sender='njorogealexw@gmail.com',
                      recipients=[email_address])
        link = url_for('change_password', token=token, _external=True)
        msg.body = "To change your password follow the link below {}".format(link)
        mail.send(msg)
    return render_template('forgotpassword.html', form=form)


@app.route('/change_password/<token>', methods=['POST', 'GET'])
def change_password(token):
    email_ = serializer.loads(token, salt='email-confirm', max_age=600)
    form = ChangePassword()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.new_password.data,
                                                 method='sha256')
        user = User.query.filter_by(email=email_).first()
        user.password = hashed_password
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('changepassword.html', form=form)


@app.route('/sendsms', methods=['POST', 'GET'])
def sendsms():
    pass
