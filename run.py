import os
from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "1").strip().lower() in {"1", "true", "yes", "on"}
    # Werkzeug guard is relaxed only for this local/demo runner.
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
