"""Main application forms for URL scanning and filtering."""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError


class UrlScanForm(FlaskForm):
    """URL scanner submission form."""
    url = StringField(
        "Target URL to Inspect",
        validators=[
            DataRequired(message="Please provide a valid URL to analyze."),
            Length(min=3, max=2048, message="URL length must be between 3 and 2048 characters.")
        ],
        render_kw={"placeholder": "e.g., https://example-verification.com/login.php", "autocomplete": "off"}
    )
    submit = SubmitField("Analyze URL")

    def validate_url(self, field):
        val = field.data.strip()
        # Disallow dangerous javascript: or data: pseudoprotocols
        if val.lower().startswith(("javascript:", "data:", "vbscript:", "file:")):
            raise ValidationError("Invalid URL scheme. Only HTTP, HTTPS, or standard web URLs are allowed.")
