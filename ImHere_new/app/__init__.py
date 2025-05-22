from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis

# Initialize extensions
db = SQLAlchemy()
mail = Mail()
socketio = SocketIO()
migrate = Migrate()
redis_client = Redis(host='localhost', port=6379, db=0)
limiter = Limiter(
    get_remote_address,
    storage_uri="redis://localhost:6379/0",
    default_limits=[]
)

def create_app(config_name='default'):
    """Application factory function to create and configure the Flask app"""
    app = Flask(__name__)

    # Load configuration
    from app.config.config import config
    app.config.from_object(config[config_name])

    # Initialize extensions with app
    db.init_app(app)
    mail.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    migrate.init_app(app, db)
    limiter.init_app(app)

    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.employee import employee_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(employee_bp)
    app.register_blueprint(admin_bp)

    # Register error handlers
    @app.errorhandler(429)
    def ratelimit_handler(e):
        from flask import render_template
        retry_after = int(e.description.split(' ')[-1]) if "Retry-After" in e.description else 60
        return render_template("429.html", retry_after=retry_after), 429

    # Context processors
    @app.context_processor
    def inject_logged_in_employee():
        from flask import session
        from app.models.employee import Employee
        if 'employee_id' in session:
            employee = Employee.query.get(session['employee_id'])
            return dict(logged_in_employee=employee, show_profile_picture=True)
        return dict(logged_in_employee=None, show_profile_picture=False)

    # Start NFC card scanner in a separate thread
    with app.app_context():
        from app.utils.nfc import start_nfc_scanner
        start_nfc_scanner()

    return app
