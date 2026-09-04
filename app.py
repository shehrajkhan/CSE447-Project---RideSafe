"""
RideSafe - Secure Ride-Sharing & Carpool Coordination App
CSE447 Project

Entry point. Registers all module blueprints so each teammate can build
their routes independently under routes/.
"""

from flask import Flask
from config import Config

# Blueprints - one per teammate's ownership area (see project roadmap)
from routes.auth import auth_bp          # whoever owns auth/keys - registration, login, 2FA hookup
from routes.profile import profile_bp    # whoever owns auth/keys - profile view/update (RSA)
from routes.keys import keys_bp          # whoever owns auth/keys - Key Management Module
from routes.trips import trips_bp        # whoever owns the skeleton/ECC work - ride requests, trip logs (ECC)
from routes.chat import chat_bp          # whoever owns the skeleton/ECC work - in-app chat (ECC + MAC)
from routes.sessions import sessions_bp  # whoever owns sessions/RBAC - session mgmt, RBAC
from routes.admin import admin_bp        # whoever owns sessions/RBAC - admin/RBAC-protected routes


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.register_blueprint(auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(trips_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(sessions_bp)
    app.register_blueprint(admin_bp)

    from flask import redirect, url_for, g, request
    from routes.sessions import validate_session

    @app.before_request
    def load_logged_in_user():
        token = request.cookies.get("session_token")
        session_data = validate_session(token)
        if session_data:
            g.user_id, g.user_role = session_data
        else:
            g.user_id, g.user_role = None, None

    @app.route("/")
    def index():
        if g.user_id:
            return redirect(url_for("trips.dashboard"))
        return redirect(url_for("auth.login"))

    return app



if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5001))
    app = create_app()
    app.run(debug=True, port=port)

