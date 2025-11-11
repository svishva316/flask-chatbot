from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import stripe
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "secret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chatbot.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Stripe setup
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Login setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
@app.route("/")
def home():
    # Redirect to login page or dashboard if already logged in
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("login"))

# -----------------------------
# DATABASE MODELS
# -----------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    message_count = db.Column(db.Integer, default=0)
    free_limit = 20  # free messages

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    sender = db.Column(db.String(10))  # "user" or "bot"
    content = db.Column(db.Text)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------------
# AUTH ROUTES
# -----------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        if User.query.filter_by(email=email).first():
            return "User already exists!"
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for("dashboard"))
        return "Invalid credentials!"
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Save user in the database here
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()

        # Optionally, log in the user right after registering
        login_user(user)

        # Redirect to dashboard after successful registration
        return redirect(url_for("dashboard"))

    return render_template("register.html")

# -----------------------------
# DASHBOARD + CHAT
# -----------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    messages = ChatMessage.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", user=current_user, user_messages=messages)


@app.route("/chat", methods=["POST"])
@login_required
def chat():
    user_message = request.json["message"]

    # Check if free limit reached
    if not current_user.is_paid:
        if current_user.message_count >= current_user.free_limit:
            return jsonify({"error": "Free limit reached. Please upgrade!"}), 403
        current_user.message_count += 1
        db.session.commit()

    # Send message to AI (OpenRouter)
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": user_message}]
    }
    res = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=data)
    bot_text = res.json()["choices"][0]["message"]["content"]

    # 💾 Save both user + bot messages
    msg_user = ChatMessage(user_id=current_user.id, sender="user", content=user_message)
    msg_bot = ChatMessage(user_id=current_user.id, sender="bot", content=bot_text)
    db.session.add_all([msg_user, msg_bot])
    db.session.commit()

    return jsonify({"reply": bot_text})

# -----------------------------
# STRIPE PAYMENT ROUTES
# -----------------------------
@app.route("/create-checkout-session")
@login_required
def create_checkout_session():
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{
            "price_data": {
                "currency": "usd",
                "product_data": {"name": "Chatbot Premium"},
                "unit_amount": 49900,  # $4.99
            },
            "quantity": 1,
        }],
        mode="payment",
        customer_email=current_user.email,
        success_url=url_for("success", _external=True),
        cancel_url=url_for("dashboard", _external=True),
    )
    return redirect(session.url, code=303)

@app.route("/success")
@login_required
def success():
    return render_template("success.html")

# -----------------------------
# STRIPE WEBHOOK
# -----------------------------
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    if event["type"] == "checkout.session.completed":
        session_data = event["data"]["object"]
        email = session_data.get("customer_email")
        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_paid = True
                db.session.commit()
    return "ok", 200

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
