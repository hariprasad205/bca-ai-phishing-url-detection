"""Authentication forms with WTForms and CSRF validation."""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from app.models import User


class RegistrationForm(FlaskForm):
    """User registration form."""
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=30, message="Username must be between 3 and 30 characters."),
            Regexp(r"^[a-zA-Z0-9_]+$", message="Username must contain only letters, numbers, and underscores.")
        ]
    )
    email = StringField(
        "Email Address",
        validators=[
            DataRequired(),
            Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Please provide a valid email address."),
            Length(max=120)
        ]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, max=64, message="Password must be at least 8 characters long.")
        ]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match.")
        ]
    )
    submit = SubmitField("Create Account")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data.strip()).first():
            raise ValidationError("This username is already taken. Please choose another.")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.strip().lower()).first():
            raise ValidationError("An account with this email address already exists.")


class LoginForm(FlaskForm):
    """User login form."""
    username_or_email = StringField(
        "Username or Email",
        validators=[DataRequired(message="Please enter your username or email address.")]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Please enter your password.")]
    )
    submit = SubmitField("Sign In")


class ProfileForm(FlaskForm):
    """User profile update form."""
    email = StringField(
        "Email Address",
        validators=[
            DataRequired(),
            Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Please provide a valid email address."),
            Length(max=120)
        ]
    )
    current_password = PasswordField("Current Password (to confirm changes)")
    new_password = PasswordField(
        "New Password (leave blank to keep unchanged)",
        validators=[Length(min=0, max=64)]
    )
    submit = SubmitField("Update Profile")
