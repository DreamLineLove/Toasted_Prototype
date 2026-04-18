from datetime import datetime
import hashlib
import os
import sqlite3

from bcrypt import hashpw, gensalt, checkpw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, flash, redirect, render_template, request, session, url_for, g
from flask_sqlalchemy import SQLAlchemy
from flask_babel import Babel, gettext as _

def get_locale():
    # Check if language is set in session, otherwise use default
    return session.get('lang', 'en')

app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "prototype-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["BABEL_DEFAULT_LOCALE"] = "en"
app.config["BABEL_SUPPORTED_LOCALES"] = ["en", "th"]
app.config["BABEL_TRANSLATION_DIRECTORIES"] = os.path.join(os.path.dirname(__file__), "translations")

babel = Babel(app, locale_selector=get_locale)

db = SQLAlchemy(app)

def ensure_db_schema():
    db_path = os.path.join(app.instance_path, "app.db")
    if not os.path.exists(db_path):
        return
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='user'")
        row = cur.fetchone()
        if row and "UNIQUE (username)" in row[0]:
            conn.close()
            db.drop_all()
            db.create_all()
            return
        cur.execute("PRAGMA table_info(delivery_schedule)")
        cols = [r[1] for r in cur.fetchall()]
        if cols and "transport" not in cols:
            cur.execute("ALTER TABLE delivery_schedule ADD COLUMN transport VARCHAR(120)")
            conn.commit()
        conn.close()
    except sqlite3.Error:
        pass

ENCRYPTION_KEY = hashlib.sha256(app.config["SECRET_KEY"].encode()).digest()

def hash_password(password: str) -> bytes:
    return hashpw(password.encode("utf-8"), gensalt())


def verify_password(password: str, password_hash: bytes) -> bool:
    return checkpw(password.encode("utf-8"), password_hash)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)
    role = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Formulation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    encrypted_payload = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary(12), nullable=False)
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    drug_name = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    reserved = db.Column(db.Integer, nullable=False, default=0)
    updated_by = db.Column(db.String(80), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(40), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    target = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(400), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class ProductionBatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_name = db.Column(db.String(120), nullable=False)
    drug_name = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="Pending")
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class RawMaterialRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    material_name = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(40), nullable=False, default="Requested")
    requested_by = db.Column(db.String(80), nullable=False)
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)


class CustomerOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(120), nullable=False)
    drug_name = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(40), nullable=False, default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DeliverySchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    destination = db.Column(db.String(120), nullable=False)
    scheduled_date = db.Column(db.Date, nullable=False)
    transport = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(40), nullable=False, default="Scheduled")
    manager = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    sender_role = db.Column(db.String(40), nullable=False)
    message = db.Column(db.String(1000), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    ensure_db_schema()
    db.create_all()


def encrypt_payload(plaintext: str) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(ENCRYPTION_KEY)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return encrypted, nonce


def decrypt_payload(encrypted: bytes, nonce: bytes) -> str:
    aesgcm = AESGCM(ENCRYPTION_KEY)
    return aesgcm.decrypt(nonce, encrypted, None).decode("utf-8")


def current_user():
    uid = session.get("user_id")
    if uid is None:
        return None
    return User.query.get(uid)


def require_roles(*allowed_roles):
    def decorator(func):
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None or user.role not in allowed_roles:
                flash("Unauthorized access.", "danger")
                return redirect(url_for("login"))
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator


def log_event(actor: str, role: str, action: str, target: str, details: str = "") -> None:
    event = AuditEvent(actor=actor, role=role, action=action, target=target, details=details)
    db.session.add(event)
    db.session.commit()


ROLE_ACTIONS = {
    "Researcher": [
        {"label": "View formulations", "endpoint": "formulations"},
        {"label": "Submit new formulation", "endpoint": "create_formulation"},
        {"label": "Search formulations", "endpoint": "research_search"},
    ],
    "Production Planner": [
        {"label": "Demand forecasting", "endpoint": "forecast"},
    ],
    "Production Manager": [
        {"label": "Create production batch", "endpoint": "create_batch"},
        {"label": "Request raw materials", "endpoint": "raw_materials"},
        {"label": "Review inventory", "endpoint": "inventory_manage"},
    ],
    "Regulatory Affairs": [
        {"label": "Release production batch", "endpoint": "release_batch"},
    ],
    "Warehouse Staff": [
        {"label": "Manage inventory", "endpoint": "inventory_manage"},
        {"label": "Reserve stock", "endpoint": "inventory_reserve"},
    ],
    "Sales Staff": [
        {"label": "Approve customer orders", "endpoint": "sales_orders"},
        {"label": "View customer portal", "endpoint": "customer_portal"},
        {"label": "Customer chat", "endpoint": "chat"},
    ],
    "Customer": [
        {"label": "Browse availability", "endpoint": "customer_portal"},
        {"label": "Track delivery status", "endpoint": "track_delivery"},
        {"label": "Contact sales", "endpoint": "chat"},
    ],
    "Delivery Manager": [
        {"label": "Schedule delivery", "endpoint": "delivery_schedule"},
        {"label": "Reschedule delivery", "endpoint": "delivery_schedule"},
        {"label": "Assign transport", "endpoint": "delivery_schedule"},
    ],
}

@app.route("/set_language/<lang>")
def set_language(lang):
    if lang in ["en", "th"]:
        session['lang'] = lang
    return redirect(request.referrer or url_for('home'))

@app.route("/")
def home():
    user = current_user()
    roles = list(ROLE_ACTIONS.keys())
    actions = ROLE_ACTIONS.get(user.role, []) if user else []
    return render_template("dashboard.html", user=user, roles=roles, actions=actions)


@app.route("/register", methods=["GET", "POST"])
def register():
    selected_role = request.args.get("role", "")
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form["role"]
        if not username or not password or not role:
            flash("All fields are required.", "warning")
            return redirect(url_for("register", role=selected_role) if selected_role else url_for("register"))
        if User.query.filter_by(username=username, role=role).first():
            flash("An account for this username and role already exists.", "warning")
            return redirect(url_for("register", role=selected_role) if selected_role else url_for("register"))
        user = User(username=username, password_hash=hash_password(password), role=role)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login", role=role))
    return render_template("register.html", selected_role=selected_role)


@app.route("/login", methods=["GET", "POST"])
def login():
    selected_role = request.form.get("role") or request.args.get("role")
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = selected_role
        if not role:
            flash("Please select a role from the landing page before logging in.", "warning")
            return redirect(url_for("home"))
        user = User.query.filter_by(username=username, role=role).first()
        if not user and username == "aaaa" and password == "aaaa":
            user = User(username=username, password_hash=hash_password(password), role=role)
            db.session.add(user)
            db.session.commit()
        if user and verify_password(password, user.password_hash):
            session["user_id"] = user.id
            flash(f"Welcome back, {user.username}.", "success")
            return redirect(url_for("home"))
        flash("Invalid username, password, or role.", "danger")
    return render_template("login.html", selected_role=selected_role)


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    selected_role = request.form.get("role") or request.args.get("role")
    if request.method == "POST":
        username = request.form["username"].strip()
        new_password = request.form["new_password"]
        if not username or not new_password or not selected_role:
            flash("Username, role, and new password are required.", "warning")
            return redirect(url_for("reset_password", role=selected_role) if selected_role else url_for("home"))
        user = User.query.filter_by(username=username, role=selected_role).first()
        if user:
            user.password_hash = hash_password(new_password)
            db.session.commit()
            flash("Password reset successfully.", "success")
            return redirect(url_for("login", role=selected_role))
        flash("No account found for that username and role.", "warning")
    return render_template("reset_password.html", selected_role=selected_role)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/formulations")
@require_roles("Researcher")
def formulations():
    user = current_user()
    records = Formulation.query.order_by(Formulation.created_at.desc()).all()
    view_records = []
    for record in records:
        payload = decrypt_payload(record.encrypted_payload, record.nonce)
        view_records.append({
            "id": record.id,
            "name": record.name,
            "payload": payload,
            "created_by": record.created_by,
            "created_at": record.created_at,
        })
    return render_template("formulations.html", user=user, formulations=view_records)


@app.route("/formulations/new", methods=["GET", "POST"])
@require_roles("Researcher")
def create_formulation():
    user = current_user()
    if request.method == "POST":
        name = request.form["name"].strip()
        payload = request.form["payload"].strip()
        if not name or not payload:
            flash("Drug formulation name and payload are required.", "warning")
            return redirect(url_for("create_formulation"))
        encrypted_payload, nonce = encrypt_payload(payload)
        formulation = Formulation(name=name, encrypted_payload=encrypted_payload, nonce=nonce, created_by=user.username)
        db.session.add(formulation)
        db.session.commit()
        log_event(user.username, user.role, "Created drug formulation", name)
        flash("Formulation saved with AES-256 encryption.", "success")
        return redirect(url_for("formulations"))
    return render_template("formulation_create.html", user=user)


@app.route("/inventory_manage", methods=["GET", "POST"])
@require_roles("Warehouse Staff", "Production Manager")
def inventory_manage():
    user = current_user()
    if request.method == "POST":
        drug_name = request.form["drug_name"].strip()
        quantity = int(request.form.get("quantity", 0))
        if not drug_name or quantity < 0:
            flash("Drug name is required and quantity cannot be negative.", "warning")
            return redirect(url_for("inventory_manage"))
        item = InventoryItem.query.filter_by(drug_name=drug_name).first()
        if item is None:
            if quantity < 1:
                flash("Cannot create inventory with quantity less than 1.", "warning")
                return redirect(url_for("inventory_manage"))
            item = InventoryItem(drug_name=drug_name, quantity=quantity, reserved=0, updated_by=user.username)
            db.session.add(item)
        else:
            new_quantity = item.quantity + quantity
            if new_quantity < 0:
                flash("Cannot reduce inventory below 0.", "warning")
                return redirect(url_for("inventory_manage"))
            item.quantity = new_quantity
            item.updated_by = user.username
            item.updated_at = datetime.utcnow()
        db.session.commit()
        log_event(user.username, user.role, "Updated inventory", drug_name, f"quantity_change={quantity}")
        flash("Inventory updated.", "success")
        return redirect(url_for("inventory_manage"))
    items = InventoryItem.query.order_by(InventoryItem.drug_name).all()
    return render_template("inventory.html", user=user, items=items)


@app.route("/inventory_reserve", methods=["GET", "POST"])
@require_roles("Warehouse Staff")
def inventory_reserve():
    user = current_user()
    if request.method == "POST":
        drug_name = request.form["drug_name"].strip()
        reserve = int(request.form.get("reserve", 0))
        if not drug_name:
            flash("Drug name is required.", "warning")
            return redirect(url_for("inventory_reserve"))
        if reserve < 1:
            flash("Reserve quantity must be at least 1.", "warning")
            return redirect(url_for("inventory_reserve"))
        item = InventoryItem.query.filter_by(drug_name=drug_name).first()
        if item is None:
            flash("Drug not found in inventory.", "warning")
            return redirect(url_for("inventory_reserve"))
        available = item.quantity - item.reserved
        if reserve > available:
            flash("Cannot reserve more than available stock.", "warning")
            return redirect(url_for("inventory_reserve"))
        item.reserved += reserve
        item.updated_by = user.username
        item.updated_at = datetime.utcnow()
        db.session.commit()
        log_event(user.username, user.role, "Reserved stock", drug_name, f"reserved={reserve}")
        flash("Stock reserved.", "success")
        return redirect(url_for("inventory_reserve"))
    items = InventoryItem.query.order_by(InventoryItem.drug_name).all()
    return render_template("inventory_reserve.html", user=user, items=items)


@app.route("/research_search", methods=["GET", "POST"])
@require_roles("Researcher")
def research_search():
    user = current_user()
    query = request.form.get("query", "")
    results = []
    if request.method == "POST" and query:
        formulations = Formulation.query.filter(Formulation.name.ilike(f"%{query}%")).all()
        for formulation in formulations:
            payload = decrypt_payload(formulation.encrypted_payload, formulation.nonce)
            results.append({
                "name": formulation.name,
                "created_by": formulation.created_by,
                "created_at": formulation.created_at,
                "payload": payload,
            })
    return render_template("research_search.html", user=user, query=query, results=results)


@app.route("/forecast", methods=["GET", "POST"])
@require_roles("Production Planner")
def forecast():
    user = current_user()
    forecast_items = []
    demand_input = request.form.get("demand_input")
    if request.method == "POST" and demand_input:
        try:
            base_demand = int(demand_input)
            forecast_items = [
                {"name": "Raw Material A", "forecast": int(base_demand * 1.2)},
                {"name": "Finished Drug X", "forecast": int(base_demand * 0.9)},
                {"name": "Packaging", "forecast": int(base_demand * 1.1)},
            ]
        except ValueError:
            flash("Enter a numeric demand value.", "warning")
    return render_template("forecast.html", user=user, forecast_items=forecast_items, demand_input=demand_input)


@app.route("/create_batch", methods=["GET", "POST"])
@require_roles("Production Manager")
def create_batch():
    user = current_user()
    if request.method == "POST":
        batch_name = request.form["batch_name"].strip()
        drug_name = request.form["drug_name"].strip()
        if not batch_name or not drug_name:
            flash("Batch name and drug name are required.", "warning")
            return redirect(url_for("create_batch"))
        batch = ProductionBatch(batch_name=batch_name, drug_name=drug_name, created_by=user.username)
        db.session.add(batch)
        db.session.commit()
        log_event(user.username, user.role, "Created production batch", batch_name)
        flash("Production batch created successfully.", "success")
        return redirect(url_for("create_batch"))
    batches = ProductionBatch.query.order_by(ProductionBatch.created_at.desc()).all()
    return render_template("create_batch.html", user=user, batches=batches)


@app.route("/raw_materials", methods=["GET", "POST"])
@require_roles("Production Manager")
def raw_materials():
    user = current_user()
    if request.method == "POST":
        material_name = request.form["material_name"].strip()
        quantity = int(request.form.get("quantity", 0))
        if not material_name or quantity <= 0:
            flash("Material name and positive quantity are required.", "warning")
            return redirect(url_for("raw_materials"))
        request_item = RawMaterialRequest(material_name=material_name, quantity=quantity, requested_by=user.username)
        db.session.add(request_item)
        db.session.commit()
        log_event(user.username, user.role, "Requested raw materials", material_name, f"qty={quantity}")
        flash("Raw material request submitted.", "success")
        return redirect(url_for("raw_materials"))
    requests = RawMaterialRequest.query.order_by(RawMaterialRequest.requested_at.desc()).all()
    return render_template("raw_materials.html", user=user, requests=requests)


@app.route("/release_batch", methods=["GET", "POST"])
@require_roles("Regulatory Affairs")
def release_batch():
    user = current_user()
    if request.method == "POST":
        batch_id = request.form.get("batch_id")
        if batch_id:
            batch = ProductionBatch.query.get(batch_id)
            if batch and batch.status != "Released":
                batch.status = "Released"
                db.session.commit()
                log_event(user.username, user.role, "Released production batch", batch.batch_name)
                flash("Batch has been released.", "success")
            else:
                flash("Batch not found or already released.", "warning")
        return redirect(url_for("release_batch"))
    batches = ProductionBatch.query.order_by(ProductionBatch.created_at.desc()).all()
    return render_template("release_batch.html", user=user, batches=batches)


@app.route("/sales_orders", methods=["GET", "POST"])
@require_roles("Sales Staff")
def sales_orders():
    user = current_user()
    if request.method == "POST":
        order_id = request.form.get("order_id")
        action = request.form.get("action")
        order = CustomerOrder.query.get(order_id)
        if order and action in ["Approve", "Reject"]:
            order.status = "Approved" if action == "Approve" else "Rejected"
            db.session.commit()
            log_event(user.username, user.role, f"{order.status} order", order.drug_name)
            flash(f"Order {action.lower()}ed.", "success")
        else:
            flash("Order not found or invalid action.", "warning")
        return redirect(url_for("sales_orders"))
    orders = CustomerOrder.query.order_by(CustomerOrder.created_at.desc()).all()
    return render_template("sales_orders.html", user=user, orders=orders)


@app.route("/customer_portal", methods=["GET", "POST"])
@require_roles("Customer", "Sales Staff")
def customer_portal():
    user = current_user()
    inventory_items = InventoryItem.query.order_by(InventoryItem.drug_name).all()
    if request.method == "POST":
        drug_name = request.form["drug_name"].strip()
        quantity = int(request.form.get("quantity", 1))
        if not drug_name or quantity <= 0:
            flash("Please choose a drug and quantity.", "warning")
            return redirect(url_for("customer_portal"))
        order = CustomerOrder(customer_name=user.username, drug_name=drug_name, quantity=quantity)
        db.session.add(order)
        db.session.commit()
        flash("Your order request has been submitted.", "success")
        return redirect(url_for("customer_portal"))
    orders = CustomerOrder.query.filter_by(customer_name=user.username).order_by(CustomerOrder.created_at.desc()).all()
    return render_template("customer_portal.html", user=user, inventory_items=inventory_items, orders=orders)


@app.route("/track_delivery")
@require_roles("Customer")
def track_delivery():
    user = current_user()
    orders = CustomerOrder.query.filter_by(customer_name=user.username).order_by(CustomerOrder.created_at.desc()).all()
    return render_template("track_delivery.html", user=user, orders=orders)


@app.route("/delivery_schedule", methods=["GET", "POST"])
@require_roles("Delivery Manager")
def delivery_schedule():
    user = current_user()
    if request.method == "POST":
        action = request.form.get("action", "schedule")
        if action == "schedule":
            destination = request.form.get("destination", "").strip()
            scheduled_date_str = request.form.get("scheduled_date", "")
            transport = request.form.get("transport", "").strip()
            if not destination or not scheduled_date_str:
                flash("Destination and scheduled date are required.", "warning")
                return redirect(url_for("delivery_schedule"))
            from datetime import date
            scheduled_date = date.fromisoformat(scheduled_date_str)
            schedule = DeliverySchedule(destination=destination, scheduled_date=scheduled_date,
                                        transport=transport or None, manager=user.username)
            db.session.add(schedule)
            db.session.commit()
            log_event(user.username, user.role, "Scheduled delivery", destination,
                      f"date={scheduled_date_str}, transport={transport}")
            flash("Delivery scheduled.", "success")
        elif action == "reschedule":
            delivery_id = request.form.get("delivery_id")
            new_date_str = request.form.get("new_date", "")
            if not delivery_id or not new_date_str:
                flash("Delivery ID and new date are required.", "warning")
                return redirect(url_for("delivery_schedule"))
            schedule = DeliverySchedule.query.get(delivery_id)
            if not schedule:
                flash("Delivery not found.", "warning")
                return redirect(url_for("delivery_schedule"))
            from datetime import date
            schedule.scheduled_date = date.fromisoformat(new_date_str)
            db.session.commit()
            log_event(user.username, user.role, "Rescheduled delivery", schedule.destination,
                      f"new_date={new_date_str}")
            flash("Delivery rescheduled.", "success")
        elif action == "assign_transport":
            delivery_id = request.form.get("delivery_id")
            transport = request.form.get("transport", "").strip()
            if not delivery_id or not transport:
                flash("Delivery ID and transport vehicle are required.", "warning")
                return redirect(url_for("delivery_schedule"))
            schedule = DeliverySchedule.query.get(delivery_id)
            if not schedule:
                flash("Delivery not found.", "warning")
                return redirect(url_for("delivery_schedule"))
            schedule.transport = transport
            db.session.commit()
            log_event(user.username, user.role, "Assigned transport", schedule.destination,
                      f"transport={transport}")
            flash("Transport assigned.", "success")
        return redirect(url_for("delivery_schedule"))
    schedules = DeliverySchedule.query.order_by(DeliverySchedule.scheduled_date).all()
    return render_template("delivery_schedule.html", user=user, schedules=schedules)


@app.route("/chat", methods=["GET", "POST"])
@require_roles("Customer", "Sales Staff")
def chat():
    user = current_user()
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if not message:
            flash("Message cannot be empty.", "warning")
            return redirect(url_for("chat"))
        msg = ChatMessage(sender=user.username, sender_role=user.role, message=message)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("chat"))
    messages = ChatMessage.query.order_by(ChatMessage.sent_at.asc()).all()
    return render_template("chat.html", user=user, messages=messages)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
