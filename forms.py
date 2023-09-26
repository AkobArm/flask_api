from wtforms import Form, PasswordField, StringField, validators


class RegistrationForm(Form):
    email = StringField('Email', [validators.Length(min=6, max=35), validators.Email()])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.Length(min=6, max=35)])


class LoginForm(Form):
    email_or_username = StringField('Email or Username', [validators.Length(min=4, max=35)])
    password = PasswordField('Password', [validators.Length(min=6, max=35)])
