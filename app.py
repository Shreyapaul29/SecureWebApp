from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_bcrypt import Bcrypt
from werkzeug.security import check_password_hash
from flask_bcrypt import generate_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db = SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager=LoginManager(app)
login_manager.login_view="login"
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )
@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))
class RegisterForm(FlaskForm):

    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=20)]
    )

    email = StringField(
        "Email",
        validators=[DataRequired(), Email()]
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8)]
    )

    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match')
        ]
    )

    submit = SubmitField("Register")
class LoginForm(FlaskForm):
    email=StringField("Email",validators=[DataRequired(),Email()])
    password=PasswordField("Password",validators=[DataRequired()])
    submit=SubmitField("Login")
@app.route("/")
def home(): return render_template("index.html")
@app.route("/register", methods=["GET", "POST"])
def register():

    form = RegisterForm()

    if form.validate_on_submit():

        # Check if username already exists
        existing_username = User.query.filter_by(
            username=form.username.data
        ).first()

        if existing_username:
            flash("Username already exists.", "danger")
            return render_template("register.html", form=form)

        # Check if email already exists
        existing_email = User.query.filter_by(
            email=form.email.data
        ).first()

        if existing_email:
            flash("Email already registered.", "danger")
            return render_template("register.html", form=form)

        # Hash password
        hashed_password = bcrypt.generate_password_hash(
            form.password.data
        ).decode("utf-8")

        # Save user
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration Successful! Please Login.", "success")

        return redirect(url_for("login"))

    return render_template("register.html", form=form)
@app.route("/login",methods=["GET","POST"])
def login():
    f=LoginForm()
    if f.validate_on_submit():
        u=User.query.filter_by(email=f.email.data).first()
        if u and bcrypt.check_password_hash(u.password,f.password.data):
            login_user(u); return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html",form=f)
@app.route("/dashboard")
@login_required
def dashboard(): return render_template("dashboard.html")
@app.route("/logout")
@login_required
def logout():
    logout_user(); return redirect(url_for("home"))
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

