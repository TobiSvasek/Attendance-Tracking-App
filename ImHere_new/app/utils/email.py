from flask import render_template, current_app, url_for
from flask_mail import Message
from app import mail

def send_reset_email(user):
    """Send password reset email to user"""
    token = user.generate_reset_token()
    reset_url = url_for('auth.reset_token', token=token, _external=True)

    html = render_template('email_templates/reset_password_email.html', reset_url=reset_url)

    msg = Message('Password Reset Request',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.
'''
    msg.html = html

    with current_app.open_resource('static/logo.png') as fp:
        msg.attach('logo.png', 'image/png', fp.read(), 'inline', headers={'Content-ID': '<logo_cid>'})

    mail.send(msg)

def send_set_details_email(user):
    """Send email to new users to set their details"""
    token = user.generate_reset_token()
    set_details_url = url_for('auth.set_details', token=token, _external=True)

    html = render_template('email_templates/set_password_email.html', set_details=set_details_url)

    msg = Message('Set Your Account Details',
                  recipients=[user.email])
    msg.body = f'''A user account has been created for you. To set your name, surname, and password, visit the following link:
{set_details_url}

If you did not expect this email, please ignore it.
'''
    msg.html = html

    with current_app.open_resource('static/logo.png') as fp:
        msg.attach('logo.png', 'image/png', fp.read(), 'inline', headers={'Content-ID': '<logo_cid>'})

    mail.send(msg)
