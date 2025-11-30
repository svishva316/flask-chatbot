from flask import Flask, render_template, request, jsonify, redirect, url_for, session,current_app, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import stripe
import requests
import os
from dotenv import load_dotenv
from flask import send_file
import openai
from io import BytesIO
from flask_migrate import Migrate
from models import db, User, ChatMessage
from werkzeug.utils import secure_filename
import time
from PIL import Image, ImageEnhance, ImageFilter
from gtts import gTTS
import uuid
import json
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import PyPDF2
import docx
import pytesseract
import base64

from websocket import WebSocketApp,create_connection, WebSocketConnectionClosedException  # from websocket-client
from flask_socketio import SocketIO, emit, join_room, leave_room
import threading


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "secret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chatbot.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.environ["OPENAI_API_KEY"]
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
db.init_app(app)
with app.app_context():
    db.create_all()
migrate = Migrate(app, db)


stripe.api_key = os.getenv("STRIPE_SECRET_KEY")


login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)



def make(text):
    return {"result": text}


@app.route('/')
def index():
    return render_template('index.html')


@app.route("/")
def home():
    
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("login"))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    message_count = db.Column(db.Integer, default=0)
    free_limit = 20  

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# Put your replicate token into environment or fill below
REPLICATE_API_TOKEN = os.environ.get("REPLICATE_API_TOKEN") or "r8_dB6efh1T8YkyawB08aFjSskqpIHKZfN4Lwycz"
REPLICATE_WS_URL = "wss://stream.api.replicate.com/v1/realtime"


                                
 

# Keep simple per-client connection state
# mapping: sid -> { "ws": websocket_connection, "thread": thread_obj, "model_session": ... }
_realtime_connections = {}

# Utility: connect to replicate and listen (runs in background thread)
def _replicate_listen_thread(sid, ws_payload):
    """
    - Creates a WS connection to Replicate and forwards messages to the client (socket io sid).
    - ws_payload must be a dict describing the initial "start" event (model, input, etc).
    - This is generic: adjust action/protocol if your chosen model requires a specific handshake.
    """
    try:
        # Build websocket connection
        ws = create_connection(
            REPLICATE_WS_URL,
            header=[
                f"Authorization: Token {REPLICATE_API_TOKEN}",
                "Sec-WebSocket-Protocol: realtime"
            ],
            timeout=30
        )

        # store connection in mapping
        _realtime_connections[sid] = _realtime_connections.get(sid, {})
        _realtime_connections[sid]["ws"] = ws

        # initial handshake: send model + input — exact format depends on model
        # Example generic message: { "type": "start", "model": "model_name", "input": {...} }
        ws.send(json.dumps(ws_payload))
        initial_msg = ws.recv()
        try:
            initial_json = json.loads(initial_msg)
        except:
            initial_json = {"type": "error", "message": "Non-JSON response from Replicate", "raw": initial_msg}

# DEBUG PRINT (you asked “WHERE?” → THIS IS THE PLACE)
        print("🛑 REPLICATE HANDSHAKE RESPONSE:", initial_json)

# If Replicate returned an error, stop immediately
        if initial_json.get("type") == "error":
            socketio.emit("replicate_error", initial_json, room=sid)
            try:
                ws.close()
            except:
                pass
            return

        # now listen and forward to client
        while True:
            try:
                msg = ws.recv()
            except WebSocketConnectionClosedException:
                break
            if msg is None:
                break

            # try decode JSON
            try:
                j = json.loads(msg)
            except Exception:
                # if not JSON, just forward raw
                socketio.emit("replicate_message", {"raw": msg}, room=sid)
                continue

            # Forward raw message to client
            socketio.emit("replicate_message", j, room=sid)
            if isinstance(j, dict):

                # CASE A: preview frame inside   j["image"]["base64"]
                if j.get("image") and isinstance(j["image"], dict):
                    b64 = j["image"].get("base64")
                    if b64:
                        socketio.emit(
                            "replicate_message",
                            {"image": {"base64": b64}},
                            room=sid
                        )

                # CASE B: preview frame inside   j["output"]
                if j.get("type") == "output" and j.get("output"):
                    socketio.emit(
                        "replicate_message",
                        {"image": {"base64": j["output"]}},
                        room=sid
                    )

            # If replicate indicates generation done, break
            # (Model-specific — adjust the condition accordingly)
            if j.get("type") in ("done", "completed") or j.get("status") == "succeeded":
                break

        try:
            ws.close()
        except:
            pass

    except Exception as e:
        socketio.emit("replicate_error", {"error": str(e)}, room=sid)
    finally:
        # cleanup
        _realtime_connections.pop(sid, None)
        socketio.emit("replicate_closed", {"msg": "connection closed"}, room=sid)

# Socket.IO events
@socketio.on("connect")
def handle_connect():
    sid = request.sid
    print(f"[socketio] client connected {sid}")
    # optional: join a room same as sid
    join_room(sid)

@socketio.on("disconnect")
def handle_disconnect():
    sid = request.sid
    print(f"[socketio] client disconnected {sid}")
    # cleanup a replicate websocket if exists
    info = _realtime_connections.get(sid)
    if info and info.get("ws"):
        try:
            info["ws"].close()
        except:
            pass
    _realtime_connections.pop(sid, None)
    leave_room(sid)

@socketio.on("start_generation")
def handle_start_generation(data):
    """
    Client will emit start_generation with:
    {
      "model": "stability/flux-1" or other,
      "input": { ... },   # model inputs, e.g., { "prompt": "..." }
      "stream_options": { ... }  # optional
    }
    """
    sid = request.sid
    model = data.get("model") or "stability/flux-1"  # change default if you want
    input_payload = data.get("input") or {}
    stream_opts = data.get("stream_options") or {}

    # Build the replicate payload (generic). You MUST adapt this block to the exact model's protocol.
    # Example minimal start message:
    payload = {
        "type": "start",
        "model": model,
        "input": input_payload,
        "stream": True,
        "stream_options": stream_opts
    }

    # Launch background thread to connect to replicate and forward messages
    t = threading.Thread(target=_replicate_listen_thread, args=(sid, payload), daemon=True)
    _realtime_connections[sid] = {"thread": t, "ws": None}
    t.start()

    emit("started", {"msg": "replicate connection started"})

@socketio.on("update_prompt")
def handle_update_prompt(data):
    """
    Called as user types. We'll forward a message to replicate WS if there's an active connection.
    Data e.g. { "prompt": "new prompt text" }
    """
    sid = request.sid
    prompt = data.get("prompt", "")
    info = _realtime_connections.get(sid)
    if not info or not info.get("ws"):
        emit("replicate_error", {"error": "No active replicate connection for live updates."})
        return

    ws = info["ws"]
    # MODEL-SPECIFIC: send an "update" message format. Some models accept {'type':'update','input':{...}}
    try:
        update_msg = {"type": "update", "input": {"prompt": prompt}}
        ws.send(json.dumps(update_msg))
        emit("ack", {"msg": "update forwarded"})
    except Exception as e:
        emit("replicate_error", {"error": str(e)})

@socketio.on("stop_generation")
def handle_stop_generation():
    sid = request.sid
    info = _realtime_connections.get(sid)
    if info and info.get("ws"):
        try:
            info["ws"].close()
        except:
            pass
    _realtime_connections.pop(sid, None)
    emit("stopped", {"msg": "generation stopped"})














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

        
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()

        
        login_user(user)

        
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/dashboard")
@login_required
def dashboard():
    messages = ChatMessage.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", user=current_user, user_messages=messages)

@app.route("/tts_new", methods=["POST"])
def tts_new():
    try:
        data = request.json
        text = data.get("text", "")
        lang = data.get("lang", "en")
        slow = data.get("slow", False)

        if not text:
            return jsonify({"error": "Text is required"}), 400

        filename = f"tts_{uuid.uuid4()}.mp3"
        filepath = os.path.join("static", filename)

        # Generate voice using gTTS
        tts = gTTS(text=text, lang=lang, slow=slow)
        tts.save(filepath)

        return jsonify({
            "status": "success",
            "audio_url": f"/static/{filename}"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stt", methods=["POST"])
def stt():
    audio_file = request.files["audio"]

    transcript = openai.audio.transcriptions.create(
        model="gpt-4o-mini-transcribe",
        file=audio_file
    )

    return {"text": transcript.text}
@app.route("/search-image", methods=["POST"])
def search_image():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image uploaded'}), 400

        file = request.files['image']
        img = Image.open(file.stream)

        # -------- BASIC ANALYSIS --------
        width, height = img.size
        mode = img.mode
        desc = f"Image size: {width}x{height}, Mode: {mode}"

        return jsonify({
            "result": desc,
            "analysis": {
                "width": width,
                "height": height,
                "mode": mode
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500





@app.route("/tools/summarizer", methods=["POST"])
def tool_summarizer():
    text = request.json.get("text", "")
    if not text:
        return make("No text provided.")
    
    sentences = text.split(".")
    short = ". ".join(sentences[:2]) + "..."
    return make(short)









@app.route("/tools/rewriter", methods=["POST"])
def tool_rewriter():
    text = request.json.get("text", "")
    if not text:
        return make("No text provided.")
    
    rewritten = text.replace("very", "extremely").replace("good", "excellent")
    return make(rewritten + "\n\n(Rewritten)")



@app.route("/tools/grammar", methods=["POST"])
def tool_grammar():
    text = request.json.get("text", "")
    fixed = text.replace(" i ", " I ").replace(" im ", " I'm ")
    return make(fixed + "\n\n(Grammar Improved)")


@app.route("/tools/expander", methods=["POST"])
def tool_expander():
    text = request.json.get("text", "")
    return make(text + "\n\nThis expands the idea further in detail.")



@app.route("/tools/codeExplain", methods=["POST"])
def tool_code_explain():
    text = request.json.get("text", "")
    return make("This code performs logical operations and flow control. (Simple explanation)")


@app.route("/tools/pdf", methods=["POST"])
def tool_pdf():
    file = request.files["file"]
    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return make(text or "No readable text found.")




@app.route("/tools/docx", methods=["POST"])
def tool_docx_reader():
    file = request.files["file"]
    doc = docx.Document(file)
    text = "\n".join([p.text for p in doc.paragraphs])
    return make(text)



@app.route("/tools/extract", methods=["POST"])
def tool_extract():
    file = request.files["file"]
    raw = file.read().decode(errors="ignore")
    return make(raw)



@app.route("/tools/ocr", methods=["POST"])
def tool_ocr():
    file = request.files["file"]
    image = Image.open(file.stream)
    text = pytesseract.image_to_string(image)
    return make(text)



@app.route("/tools/enhance", methods=["POST"])
def tool_enhance():
    file = request.files["file"]
    img = Image.open(file.stream)

    enhancer = ImageEnhance.Sharpness(img)
    enhanced = enhancer.enhance(2.0)

    buf = io.BytesIO()
    enhanced.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()

    return make(f"data:image/png;base64,{b64}")



@app.route("/tools/imggen", methods=["POST"])
def tools_imggen():
    try:
        data = request.get_json()
        prompt = data.get("prompt", "")

        # Fallback image generator (simple, never crashes)
        from PIL import Image, ImageDraw

        img = Image.new("RGB", (1024, 1024), color=(30, 30, 30))
        draw = ImageDraw.Draw(img)
        draw.text((40, 40), f"Generated Image\n\nPrompt:\n{prompt}", fill=(255, 255, 255))

        img_path = "generated_output.png"
        img.save(img_path)

        return send_file(img_path, mimetype="image/png")

    except Exception as e:
        print("\n❌ IMGGEN ERROR:", e)
        return jsonify({"error": str(e)}), 500








def _hf_headers(extra=None):
    token = os.environ.get("HF_TOKEN", "").strip()
    headers = {"Accept": "application/octet-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra:
        headers.update(extra)
    return headers

# Helper: call a remote model inference endpoint that returns binary (image/model)
def _call_binary_model(model_url, files=None, json_payload=None, headers=None, timeout=120):
    headers = headers or _hf_headers()
    # If files provided (multipart)
    if files:
        resp = requests.post(model_url, headers=headers, files=files, timeout=timeout)
    else:
        # JSON POST
        headers["Content-Type"] = "application/json"
        resp = requests.post(model_url, headers=headers, json=json_payload, timeout=timeout)
    return resp





@app.route("/tools/inpaint", methods=["POST"])
def tools_inpaint():
    """
    Expects multipart/form-data with:
      - file: image (png/jpg). This can be either:
          a) full RGBA image where transparent areas are mask, or
          b) image with mask drawn (red overlay), or
          c) separate mask file key 'mask' (optional)
    Returns: image/png binary
    """
    try:
        if "file" not in request.files:
            return jsonify({"error": "Missing file"}), 400

        img = request.files["file"]
        mask = request.files.get("mask")  # optional

        # Build model endpoint from env or use default placeholder
        model = os.environ.get("INPAINT_MODEL", "stabilityai/stable-diffusion-x-inpaint")  # set to a valid model id
        hf_url = os.environ.get("HF_INFERENCE_URL") or f"https://api-inference.huggingface.co/models/{model}"

        # If the target inference accepts multipart with image and mask, send both.
        files = {"image": (img.filename, img.stream.read())}
        if mask:
            files["mask"] = (mask.filename, mask.stream.read())

        # Many HF image endpoints accept 'inputs' JSON; but often multipart works too.
        # We'll try multipart first (works for some endpoints). If that fails, you'd adapt to the specific model's API.
        resp = _call_binary_model(hf_url, files=files)

        if resp.status_code != 200:
            # Attempt JSON approach fallback (for models expecting a JSON "inputs")
            try:
                img.stream.seek(0)
                b = img.read()
                payload = {"inputs": "", "options": {"wait_for_model": True}}
                # Some endpoints accept base64 encoded image in payload; adaptation may be required.
                frag = requests.post(hf_url, headers=_hf_headers({"Content-Type":"application/json"}), json=payload, timeout=120)
                if frag.status_code == 200:
                    return Response(frag.content, mimetype="image/png")
            except Exception:
                pass

            return jsonify({"error": "Model call failed", "status": resp.status_code, "details": resp.text}), 500

        return Response(resp.content, mimetype="image/png")
    except Exception as e:
        current_app.logger.exception("inpaint error")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


# 2) Face enhancement endpoint (ESRGAN/GFPGAN or other)
@app.route("/tools/face_enhance", methods=["POST"])
def tools_face_enhance():
    """
    Expects file: image.
    Returns enhanced image binary (PNG).
    """
    try:
        if "file" not in request.files:
            return jsonify({"error": "Missing file"}), 400
        img = request.files["file"]

        model = os.environ.get("FACE_MODEL", "facebook/gfpgan")  # set to a concrete model id suitable for face enhancement
        hf_url = os.environ.get("HF_FACE_URL") or f"https://api-inference.huggingface.co/models/{model}"

        files = {"image": (img.filename, img.stream.read())}
        resp = _call_binary_model(hf_url, files=files)

        if resp.status_code != 200:
            return jsonify({"error": "Face enhancement failed", "status": resp.status_code, "details": resp.text}), 500

        return Response(resp.content, mimetype="image/png")
    except Exception as e:
        current_app.logger.exception("face_enhance error")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


# 3) Background replacement endpoint
@app.route("/tools/bg_replace", methods=["POST"])
def tools_bg_replace():
    """
    Expects multipart/form-data:
      - file: source image
      - prompt: new background description (form field)
    Returns: image/png
    """
    try:
        if "file" not in request.files:
            return jsonify({"error": "Missing file"}), 400

        img = request.files["file"]
        prompt = request.form.get("prompt", "") or (request.json and request.json.get("prompt", ""))

        if not prompt:
            return jsonify({"error": "Missing prompt for background replacement"}), 400

        model = os.environ.get("BG_MODEL", "some/bg-replace-model")  # replace with an actual model id
        hf_url = os.environ.get("HF_BG_URL") or f"https://api-inference.huggingface.co/models/{model}"

        # Many background-removal/replacement pipelines expect both the image and a text prompt.
        # We'll send as multipart with fields. Adapt to your chosen model's required format.
        files = {
            "image": (img.filename, img.stream.read()),
            "prompt": (None, prompt)
        }

        resp = _call_binary_model(hf_url, files=files)

        if resp.status_code != 200:
            return jsonify({"error": "Background replacement failed", "status": resp.status_code, "details": resp.text}), 500

        return Response(resp.content, mimetype="image/png")

    except Exception as e:
        current_app.logger.exception("bg_replace error")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


# 4) Text → 3D model (returns a GLB/OBJ binary)
@app.route("/tools/text3d", methods=["POST"])
def tools_text3d():
    """
    Expects JSON: { "prompt": "describe 3D model" }
    Returns: application/octet-stream (GLB) or JSON error.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        prompt = data.get("prompt", "").strip()
        if not prompt:
            return jsonify({"error": "Missing prompt"}), 400

        # Endpoint configuration (model should be a 3D generator model / API)
        model = os.environ.get("TEXT3D_MODEL", "3d-model-generator/example")  # replace with real model id
        hf_url = os.environ.get("HF_TEXT3D_URL") or f"https://api-inference.huggingface.co/models/{model}"

        payload = {"inputs": prompt, "options": {"wait_for_model": True}}

        # Some 3D model endpoints return a URL or return the binary directly. We attempt JSON then binary handling.
        resp = _call_binary_model(hf_url, json_payload=payload)

        if resp.status_code == 200:
            # If the model returns a GLB/OBJ binary payload (content-type octet-stream)
            ct = resp.headers.get("content-type", "")
            if "application/octet-stream" in ct or "model/gltf-binary" in ct or "application/gltf+json" in ct:
                # return binary model
                return Response(resp.content, mimetype=ct or "application/octet-stream")
            else:
                # Many inference APIs return JSON with a download URL or base64 field
                try:
                    j = resp.json()
                    # example: { "model_url": "https://..." } or { "file": "base64..." }
                    if "model_url" in j:
                        r2 = requests.get(j["model_url"], timeout=120)
                        return Response(r2.content, mimetype=r2.headers.get("content-type", "application/octet-stream"))
                    if "file" in j:  # base64 payload
                        import base64
                        b = base64.b64decode(j["file"])
                        return Response(b, mimetype="application/octet-stream")
                except Exception:
                    pass

        return jsonify({"error": "3D generation failed", "status": resp.status_code, "details": resp.text}), 500

    except Exception as e:
        current_app.logger.exception("text3d error")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


# 5) Upscale endpoint (used by frontend 'upscaleSingle')
@app.route("/tools/upscale", methods=["POST"])
def tools_upscale():
    try:
        # Accept either multipart file or base64 string
        if "file" in request.files:
            file = request.files["file"]
            payload_files = {"image": (file.filename, file.stream.read())}
        else:
            # Accept JSON base64 payload
            data = request.get_json(force=True, silent=True) or {}
            b64 = data.get("b64")
            if not b64:
                return jsonify({"error": "No file provided"}), 400
            import base64
            payload_files = {"image": ("img.png", base64.b64decode(b64))}

        model = os.environ.get("UPSCALE_MODEL", "stabilityai/esrgan")  # example
        hf_url = os.environ.get("HF_UPSCALE_URL") or f"https://api-inference.huggingface.co/models/{model}"

        resp = _call_binary_model(hf_url, files=payload_files)

        if resp.status_code != 200:
            return jsonify({"error": "Upscale failed", "status": resp.status_code, "details": resp.text}), 500

        return Response(resp.content, mimetype="image/png")
    except Exception as e:
        current_app.logger.exception("upscale error")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500













@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

    return {"message": "File uploaded", "filename": filename}

@app.route("/chat_page")
@login_required
def chat_page():
    return render_template("chat.html")


@app.route("/chat", methods=["POST"])
@login_required
def chat():
    try:
        user_message = request.json.get("message")
        model_to_use = request.json.get("model", "meta-llama/llama-3.3-70b-instruct")

        system_prompt = """
        You are ChatGPT 5.1 — an advanced AI assistant.
        Your responses must be:
        - Perfect markdown
        - Clean and readable
        - No chain-of-thought
        - Always follow ChatGPT style
        """

        def generate():
            url = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model_to_use,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                "stream": True
            }

            with requests.post(url, headers=headers, json=payload, stream=True) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if line:
                        if line.startswith(b"data: "):
                            chunk = line.replace(b"data: ", b"").decode("utf-8")
                            if chunk == "[DONE]":
                                break
                            yield f"{chunk}\n\n"

        return Response(generate(), mimetype="text/event-stream")

    except Exception as e:
        print("SERVER ERROR:", e)
        return jsonify({"reply": "Server Error"}), 500




@app.route("/history", methods=["GET"])
@login_required
def history():
    messages = ChatMessage.query.filter_by(user_id=current_user.id)\
                                .order_by(ChatMessage.timestamp.asc()).all()

    history_data = [
        {"sender": m.sender, "content": m.content, "timestamp": m.timestamp}
        for m in messages
    ]

    return jsonify(history_data)
@app.route('/tts-download', methods=['POST'])
def tts_download():
    import edge_tts
    import asyncio
    import uuid
    import json

    text = request.form.get("text", "")
    filename = f"{uuid.uuid4()}.mp3"
    filepath = f"static/{filename}"

    async def make_voice():
        communicate = edge_tts.Communicate(text, "en-US-AriaNeural")
        await communicate.save(filepath)

    asyncio.run(make_voice())
    return send_file(filepath, as_attachment=True)



@app.route("/generate-image", methods=["POST"])
def generate_image():
    try:
        data = request.get_json()
        prompt = data.get("prompt")
        if not prompt:
            return jsonify({"error": "Prompt is required"}), 400

        API_KEY = os.getenv("HORD_API_KEY", "NQRhC0ZzbWNUzf-FS0hQQw")  
        headers = {
            "apikey": API_KEY,
            "Client-Agent": "my-flask-app/1.0"
        }

        payload = {
            "prompt": prompt,
            "params": {
                "width": 512,
                "height": 512,
                "steps": 20
            },
            "nsfw": False,
            "models": ["stable_diffusion"]
        }

       
        r = requests.post("https://stablehorde.net/api/v2/generate/async", json=payload, headers=headers)
        r.raise_for_status()
        task = r.json()
        task_id = task.get("id")
        if not task_id:
            return jsonify({"error": "Failed to start generation"}), 500

        
        return jsonify({"task_id": task_id})

    except Exception as e:
        current_app.logger.error(f"Image generation error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/generate-image/status/<task_id>", methods=["GET"])
def image_status(task_id):
    try:
        API_KEY = os.getenv("HORD_API_KEY", "NQRhC0ZzbWNUzf-FS0hQQw")
        headers = {
            "apikey": API_KEY,
            "Client-Agent": "my-flask-app/1.0"
        }

        status_url = f"https://stablehorde.net/api/v2/generate/check/{task_id}"
        r = requests.get(status_url, headers=headers)
        r.raise_for_status()
        status = r.json()

        if status.get("done") == 1:
            
            result_url = f"https://stablehorde.net/api/v2/generate/status/{task_id}"
            res = requests.get(result_url, headers=headers).json()
            images = [g.get("img") for g in res.get("generations", []) if g.get("img")]
            return jsonify({"done": True, "images": images})
        else:
            return jsonify({"done": False})

    except Exception as e:
        current_app.logger.error(f"Image status error: {e}")
        return jsonify({"error": str(e)}), 500
@app.route("/chat-ui")
@login_required
def chat_ui():
    return render_template("chat.html")
@app.route("/search", methods=["POST"])
def google_search():
    data = request.get_json()
    query = data.get("query")

    
    return jsonify({"result": f"Searching Google for: {query}"})
@app.route("/generate-pdf", methods=["POST"])
def generate_pdf():
    try:
        data = request.get_json()
        text = data.get("text", "")

        if not text:
            return jsonify({"error": "No text received"}), 400

        filename = f"pdf_{uuid.uuid4()}.pdf"
        filepath = os.path.join("static", filename)

        c = canvas.Canvas(filepath, pagesize=letter)
        width, height = letter
        y = height - 40

        # Write text line by line
        for line in text.split("\n"):
            c.drawString(50, y, line)
            y -= 20
            if y < 50:
                c.showPage()
                y = height - 40

        c.save()

        return jsonify({
            "status": "success",
            "pdf_url": f"/static/{filename}"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500




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




@app.route("/is-logged-in")
def is_logged_in():
    from flask_login import current_user
    return {"logged_in": current_user.is_authenticated}

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
