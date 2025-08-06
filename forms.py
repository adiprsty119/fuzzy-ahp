# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Email

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

# class SettingsForm(FlaskForm):
#     nama_lengkap = StringField('Nama Lengkap', validators=[DataRequired()])
#     username = StringField('Username', validators=[DataRequired()])
#     email = StringField('Email', validators=[Email()])
#     nomor_hp = StringField('Nomor HP')
#     jenis_kelamin = SelectField('Jenis Kelamin', choices=[('Laki-Laki', 'Laki-Laki'), ('Perempuan', 'Perempuan')])
#     usia = StringField('Usia')
#     foto = FileField('Foto')
#     old_password = PasswordField('Password Lama')
#     new_password = PasswordField('Password Baru')
#     confirm_password = PasswordField('Ulangi Password')