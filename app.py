from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length

# Inicjalizacja aplikacji Flask
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Klucz do sesji (w produkcji zmień na coś bardziej skomplikowanego)

# Prosty "baza danych" dla użytkowników
users = {}

# Formularz rejestracji
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=32)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=64)])

# Formularz logowania
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=32)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=64)])

@app.route('/')
def home():
    form = LoginForm()

    # Jeśli użytkownik jest zalogowany, przekieruj go na stronę powitalną
    if 'username' in session:
        return redirect(url_for('welcome'))

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data

        # Sprawdzamy, czy użytkownik już istnieje
        if username in users:
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        # Dodajemy użytkownika do naszej "bazy danych"
        users[username] = {'email': email, 'password': password}
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('home'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Sprawdzamy, czy użytkownik istnieje i czy hasło jest poprawne
        if username in users and users[username]['password'] == password:
            session['username'] = username
            flash('You have logged in successfully!', 'success')
            return redirect(url_for('welcome'))
        else:
            flash('Invalid credentials, please try again.', 'danger')

    return redirect(url_for('home'))

@app.route('/welcome')
def welcome():
    # Jeśli użytkownik nie jest zalogowany, przekieruj go na stronę logowania
    if 'username' not in session:
        return redirect(url_for('home'))

    username = session['username']
    return f'Welcome {username}! You are logged in.'

@app.route('/logout')
def logout():
    # Usuwamy użytkownika z sesji
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
