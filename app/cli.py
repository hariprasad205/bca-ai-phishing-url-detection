"""Custom Flask CLI commands for administration and maintenance."""
import os
import re
import click
from flask.cli import with_appcontext
from app.extensions import db
from app.models import User, AuditLog


def register_cli_commands(app):
    """Register custom CLI commands with the Flask application."""

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True, help="Administrator username")
    @click.option("--email", prompt=True, help="Administrator email address")
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Administrator password")
    @with_appcontext
    def create_admin_command(username, email, password):
        """Create the initial or an additional administrator account securely."""
        username = username.strip()
        email = email.strip().lower()

        # Validate username
        if not re.match(r"^[a-zA-Z0-9_]{3,30}$", username):
            click.secho("Error: Username must be 3-30 alphanumeric or underscore characters.", fg="red")
            return

        # Validate email
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            click.secho("Error: Invalid email format.", fg="red")
            return

        # Validate password strength (min 8 chars)
        if len(password) < 8:
            click.secho("Error: Password must be at least 8 characters in length.", fg="red")
            return

        # Check existing user
        if User.query.filter((User.username == username) | (User.email == email)).first():
            click.secho("Error: A user with that username or email already exists.", fg="red")
            return

        admin_user = User(
            username=username,
            email=email,
            role="admin",
            is_active_account=True,
        )
        admin_user.set_password(password)
        db.session.add(admin_user)
        db.session.flush()

        log = AuditLog(
            user_id=admin_user.id,
            action="ADMIN_CREATED_CLI",
            details=f"Administrator user '{username}' created via CLI tool.",
            ip_address="127.0.0.1",
        )
        db.session.add(log)
        db.session.commit()

        click.secho(f"Success: Administrator account '{username}' successfully created!", fg="green", bold=True)

    @app.cli.command("init-db")
    @with_appcontext
    def init_db_command():
        """Initialize database tables."""
        db.create_all()
        click.secho("Database tables initialized successfully.", fg="green")

    @app.cli.command("seed-demo-data")
    @with_appcontext
    def seed_demo_data_command():
        """Seed sample dataset and train baseline models for instant academic demo."""
        from app.ml.dataset_service import create_or_load_sample_dataset
        from app.ml.training_service import run_training_pipeline

        click.echo("Generating verified sample dataset of phishing and legitimate URLs...")
        dataset = create_or_load_sample_dataset()
        click.secho(f"Dataset ready: ID={dataset.id}, rows={dataset.total_rows} ({dataset.phishing_count} phishing, {dataset.legitimate_count} legitimate)", fg="cyan")

        click.echo("Executing ML training pipeline (Logistic Regression, Random Forest, Decision Tree)...")
        run_record, active_model = run_training_pipeline(dataset.id, initiated_by_id=None)

        if active_model:
            click.secho(f"Training Complete! Active Model: {active_model.name} (v{active_model.version})", fg="green", bold=True)
            click.echo(f"Metrics -> Accuracy: {active_model.accuracy:.4f}, Recall: {active_model.recall_score:.4f}, F1: {active_model.f1_score:.4f}, Latency: {active_model.avg_latency_ms:.2f}ms")
        else:
            click.secho(f"Training run completed with status: {run_record.status}. Notice: {run_record.error_message}", fg="yellow")
