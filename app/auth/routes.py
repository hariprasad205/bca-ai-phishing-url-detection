"""Authentication routes (Registration, Login, Logout, Profile)."""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db
from app.models import User, AuditLog
from app.auth.forms import RegistrationForm, LoginForm, ProfileForm

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Register a standard user account."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role="user",
            is_active_account=True,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        log = AuditLog(
            user_id=user.id,
            action="USER_REGISTERED",
            details=f"New user registered: {user.username} ({user.email})",
            ip_address=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()

        flash("Account created successfully! You may now sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Sign in an existing user."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.username_or_email.data.strip()
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash("Your account has been deactivated. Please contact an administrator.", "danger")
                return render_template("auth/login.html", form=form)

            login_user(user)

            log = AuditLog(
                user_id=user.id,
                action="USER_LOGIN",
                details=f"Successful authentication for user: {user.username}",
                ip_address=request.remote_addr,
            )
            db.session.add(log)
            db.session.commit()

            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("admin.admin_dashboard" if user.is_admin else "main.dashboard"))
        else:
            flash("Invalid username/email or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    """Sign out current user."""
    log = AuditLog(
        user_id=current_user.id,
        action="USER_LOGOUT",
        details=f"User signed out: {current_user.username}",
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()

    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """User profile management."""
    form = ProfileForm(email=current_user.email)
    if form.validate_on_submit():
        # If changing password, verify current password
        if form.new_password.data:
            if not form.current_password.data or not current_user.check_password(form.current_password.data):
                flash("Current password must be provided and correct to set a new password.", "danger")
                return render_template("auth/profile.html", form=form)
            current_user.set_password(form.new_password.data)

        # Check email uniqueness if modified
        new_email = form.email.data.strip().lower()
        if new_email != current_user.email:
            existing = User.query.filter_by(email=new_email).first()
            if existing and existing.id != current_user.id:
                flash("That email address is already in use by another account.", "danger")
                return render_template("auth/profile.html", form=form)
            current_user.email = new_email

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("auth.profile"))

    return render_template("auth/profile.html", form=form)
