"""Administrator forms for dataset uploading and model controls."""
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField, SelectField


class DatasetUploadForm(FlaskForm):
    """Dataset upload form accepting CSV files only."""
    csv_file = FileField(
        "CSV Dataset File",
        validators=[
            FileRequired(message="Please select a CSV file to upload."),
            FileAllowed(["csv"], "Only CSV (.csv) files are permitted.")
        ]
    )
    submit = SubmitField("Upload & Validate Dataset")


class TrainModelsForm(FlaskForm):
    """Model training trigger form."""
    dataset_id = SelectField("Select Dataset", coerce=int)
    submit = SubmitField("Start Model Training Pipeline")
