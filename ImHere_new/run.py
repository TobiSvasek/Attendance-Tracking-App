from app import create_app, socketio, db
from pyngrok import ngrok, conf
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create the application instance
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Configure ngrok
    conf.get_default().config_path = os.getenv('CONFIG_PATH')
    conf.get_default().auth_token = os.getenv('NGROK_AUTH_TOKEN')

    # Start ngrok tunnel
    public_url = ngrok.connect(5000)
    print(" * ngrok tunnel \"{}\" -> \"http://127.0.0.1:5000\"".format(public_url))

    # Run the app with SocketIO
    socketio.run(app, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)

