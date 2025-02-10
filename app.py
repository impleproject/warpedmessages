from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  # Plik bazy danych
app.config["SECRET_KEY"] = "supersecretkey"  # Klucz sesji (zmień go!)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Model użytkownika
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Formularz rejestracji
class RegisterForm(FlaskForm):
    username = StringField("Nazwa użytkownika", validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField("Hasło", validators=[InputRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField("Potwierdź hasło", validators=[InputRequired(), EqualTo("password")])
    submit = SubmitField("Zarejestruj się")

    # Sprawdzamy, czy nazwa użytkownika jest unikalna
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("Ta nazwa użytkownika jest już zajęta!")

# Formularz logowania
class LoginForm(FlaskForm):
    username = StringField("Nazwa użytkownika", validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField("Hasło", validators=[InputRequired(), Length(min=6, max=20)])
    submit = SubmitField("Zaloguj się")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Tworzenie bazy
with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Konto utworzone! Możesz się zalogować.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Zalogowano pomyślnie!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Niepoprawne dane logowania", "danger")
    return render_template("login.html", form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    return f"Witaj {current_user.username}! To twoja strona główna."

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Wylogowano!", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
