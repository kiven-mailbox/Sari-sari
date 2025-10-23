import os
import json
from calendar import month_abbr
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, send_file, abort)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import io, csv, urllib.parse
from functools import wraps

# ---------- CONFIG ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH = os.path.join(INSTANCE_DIR, "store.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")

os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("APP_SECRET", "change_this_secret_for_prod")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4MB

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------- MODELS ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="customer")  # admin or customer
    created_at = db.Column(db.String(80), default=lambda: datetime.utcnow().isoformat())

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    cost_price = db.Column(db.Float, nullable=False, default=0.0)  # real price
    price = db.Column(db.Float, nullable=False, default=0.0)       # selling price
    stock = db.Column(db.Integer, default=0)
    image = db.Column(db.String(255), nullable=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(160), nullable=True)
    total = db.Column(db.Float, nullable=False, default=0.0)
    status = db.Column(db.String(30), nullable=False, default="pending")
    created_at = db.Column(db.String(80), default=lambda: datetime.utcnow().isoformat())

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"))
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    quantity = db.Column(db.Integer, default=1)

    # store product snapshot for order review (keeps name/price even if product changes later)
    product_name = db.Column(db.String(200))
    price = db.Column(db.Float, default=0.0)
    total = db.Column(db.Float, default=0.0)

    product = db.relationship("Product", lazy="joined")

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Float, nullable=False)
    sold_at = db.Column(db.String(80), default=lambda: datetime.utcnow().isoformat())

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(120))
    action = db.Column(db.String(200))
    meta = db.Column(db.Text, default="")
    created_at = db.Column(db.String(80), default=lambda: datetime.utcnow().isoformat())

# ---------- UTIL ----------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

def log_action(actor, action, meta=""):
    try:
        a = AuditLog(actor=actor, action=action, meta=meta)
        db.session.add(a)
        db.session.commit()
    except Exception:
        db.session.rollback()

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return func(*args, **kwargs)
    return wrapper

# ---------- INIT DB & DEFAULT ADMIN ----------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        pw = generate_password_hash("admin123")
        u = User(username="admin", password=pw, role="admin")
        db.session.add(u)
        db.session.commit()
        log_action("system", "created_default_admin", "username=admin")

# ---------- DEBUG helpers ----------
@app.route("/debug_status")
def debug_status():
    tpl_exists = os.path.exists(os.path.join(BASE_DIR, "templates", "shop.html"))
    db_exists = os.path.exists(DB_PATH)
    try:
        product_count = Product.query.count()
    except Exception:
        product_count = "db-error"
    return {
        "app_running": True,
        "templates/shop.html_exists": tpl_exists,
        "db_path": DB_PATH,
        "db_exists": db_exists,
        "product_count": product_count
    }

@app.route("/seed_sample")
def seed_sample():
    try:
        if Product.query.count() == 0:
            p1 = Product(name="Coke (330ml)", description="Cold drink", price=20.0, stock=10, image="coke.png", cost_price=12.0)
            p2 = Product(name="Chips (Small)", description="Snack", price=15.0, stock=20, image="chips.png", cost_price=8.0)
            p3 = Product(name="Instant Noodles", description="Quick meal", price=30.0, stock=12, image="noodles.png", cost_price=18.0)
            db.session.add_all([p1, p2, p3])
            db.session.commit()
            return "Seeded 3 products. Go to /shop"
        else:
            return f"Products already exist: {Product.query.count()}"
    except Exception as e:
        return f"Seed failed: {e}"

# ---------- SHOP (customer-facing) ----------
@app.route("/")
def home():
    return redirect(url_for("shop"))

@app.route("/shop")
def shop():
    products = Product.query.filter(Product.stock > 0).order_by(Product.name).all()
    return render_template("shop.html", products=products)

@app.route("/product/<int:pid>")
def product_detail(pid):
    p = db.session.get(Product, pid)
    if not p:
        abort(404)
    return render_template("product_detail.html", product=p)

def cart_total_and_count():
    cart = session.get("cart", {})
    total = 0
    count = 0
    items = []
    for pid_str, qty in cart.items():
        try:
            pid = int(pid_str)
            p = db.session.get(Product, pid)
            if p:
                items.append({"product": p, "qty": qty, "line_total": round(p.price * qty, 2)})
                total += p.price * qty
                count += qty
        except Exception:
            continue
    return round(total, 2), count, items

@app.route("/cart/add/<int:pid>", methods=["POST"])
def cart_add(pid):
    if current_user.is_authenticated and current_user.role == "admin":
        flash("Admins cannot place orders.", "warning")
        return redirect(url_for("shop"))

    try:
        qty = int(request.form.get("quantity", 1))
        if qty < 1:
            qty = 1
    except Exception:
        qty = 1

    p = db.session.get(Product, pid)
    if not p:
        flash("Product not found.", "danger")
        return redirect(url_for("shop"))
    if p.stock < qty:
        flash("Not enough stock for that product.", "danger")
        return redirect(request.referrer or url_for("shop"))

    cart = session.get("cart", {})
    cart[str(pid)] = cart.get(str(pid), 0) + qty
    session["cart"] = cart
    flash(f"Added {qty} x {p.name} to cart.", "success")
    return redirect(request.referrer or url_for("shop"))

@app.route("/cart")
def cart_view():
    if current_user.is_authenticated and current_user.role == "admin":
        flash("Admins cannot access the cart.", "warning")
        return redirect(url_for("shop"))
    total, count, items = cart_total_and_count()
    return render_template("cart.html", items=items, total=total, count=count)

@app.route("/cart/remove/<int:pid>", methods=["POST"])
def cart_remove(pid):
    cart = session.get("cart", {})
    if str(pid) in cart:
        del cart[str(pid)]
        session["cart"] = cart
        flash("Item removed from cart.", "success")
    return redirect(url_for("cart_view"))

@app.route("/checkout", methods=["GET","POST"])
def checkout():
    if current_user.is_authenticated and current_user.role == "admin":
        flash("Admins cannot checkout.", "warning")
        return redirect(url_for("shop"))

    total, count, items = cart_total_and_count()
    if count == 0:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("shop"))
    if request.method == "POST":
        name = request.form.get("customer_name", "").strip() or (current_user.username if current_user.is_authenticated else "Guest")
        order = Order(customer_name=name, total=total, status="pending")
        db.session.add(order)
        db.session.commit()

        # create order items (snapshot product details)
        for it in items:
            p = it["product"]
            db_item = OrderItem(
                order_id=order.id,
                product_id=p.id,
                quantity=it["qty"],
                product_name=p.name,
                price=p.price,
                total=round(p.price * it["qty"], 2)
            )
            db.session.add(db_item)
        db.session.commit()

        session.pop("cart", None)
        log_action(name or "guest", "created_order", f"order_id={order.id} total={total}")
        return redirect(url_for("checkout_qr", order_id=order.id))
    return render_template("checkout.html", items=items, total=total)

@app.route("/checkout/<int:order_id>/qr")
def checkout_qr(order_id):
    order = db.session.get(Order, order_id)
    if not order:
        abort(404)
    pay_text = f"Pay ₱{order.total:.2f} to GCash 09171234567 for Order #{order.id}"
    qr_payload = urllib.parse.quote(pay_text)
    qr_url = f"https://chart.googleapis.com/chart?chs=300x300&cht=qr&chl={qr_payload}"
    return render_template("checkout_qr.html", order=order, qr_url=qr_url, pay_text=pay_text)

# ---------- AUTH ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        # Prevent logged-in users from seeing signup page
        flash("You are already logged in.", "info")
        return redirect(url_for("shop"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password required.", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for("signup"))

        pw = generate_password_hash(password)
        u = User(username=username, password=pw, role="customer")
        db.session.add(u)
        db.session.commit()
        log_action(username, "signup", "")
        flash("Account created. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        # Redirect logged-in users directly to their dashboard
        return redirect(url_for("admin_dashboard") if current_user.role == "admin" else url_for("shop"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            log_action(user.username, "login", f"role={user.role}")
            flash(f"Welcome back, {user.username}.", "success")
            return redirect(url_for("admin_dashboard") if user.role == "admin" else url_for("shop"))

        flash("Invalid credentials.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_action(current_user.username, "logout", f"role={current_user.role}")
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ---------- ADMIN ----------
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = User.query.filter_by(username=username).first()
        if user and user.role == "admin" and check_password_hash(user.password, password):
            login_user(user)
            log_action(user.username, "login", "role=admin")
            flash("Welcome back, admin.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials.", "danger")
    return render_template("admin_login.html")

@app.route("/admin/logout")
@login_required
@admin_required
def admin_logout():
    log_action(current_user.username, "logout", "role=admin")
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    products = Product.query.order_by(Product.name).all()
    orders = Order.query.order_by(Order.id.desc()).limit(8).all()

    total_products = len(products)
    total_orders = Order.query.count()
    pending_orders = Order.query.filter_by(status="pending").count()
    completed_orders = Order.query.filter_by(status="paid").count()
    canceled_orders = Order.query.filter_by(status="canceled").count()

    # ---- Aggregate sales from both Sale table and paid OrderItems ----
    sales_data = {}
    total_income = 0.0
    total_revenue = 0.0
    total_quantity_sold = 0

    # 1️⃣ Sales table
    sales_rows = Sale.query.order_by(Sale.sold_at.desc()).all()
    for s in sales_rows:
        pid = s.product_id
        qty = int(s.quantity or 0)
        revenue = float(s.total or 0.0)
        total_revenue += revenue
        total_quantity_sold += qty

        p = db.session.get(Product, pid)
        cost = float(p.cost_price or 0.0) if p else 0.0
        profit = revenue - (cost * qty)
        name = p.name if p else f"Product #{pid}"

        if name not in sales_data:
            sales_data[name] = {"qty": 0, "revenue": 0.0, "profit": 0.0}
        sales_data[name]["qty"] += qty
        sales_data[name]["revenue"] += revenue
        sales_data[name]["profit"] += profit
        total_income += profit

    # 2️⃣ Paid OrderItems (for products not yet in Sale table)
    paid_order_items = (
        OrderItem.query.join(Order, Order.id == OrderItem.order_id)
        .filter(Order.status == "paid")
        .all()
    )
    for it in paid_order_items:
        name = it.product_name or (it.product.name if it.product else f"Product #{it.product_id}")
        qty = int(it.quantity or 0)
        revenue = float(getattr(it, "total", 0.0) or 0.0)

        total_revenue += revenue
        total_quantity_sold += qty

        p = db.session.get(Product, it.product_id)
        cost = float(p.cost_price or 0.0) if p else 0.0
        profit = revenue - (cost * qty)

        if name not in sales_data:
            sales_data[name] = {"qty": 0, "revenue": 0.0, "profit": 0.0}
        sales_data[name]["qty"] += qty
        sales_data[name]["revenue"] += revenue
        sales_data[name]["profit"] += profit
        total_income += profit

    # --- Top products aggregation ---
    all_products = [{"name": n, **v} for n, v in sales_data.items()]
    all_products_sorted = sorted(all_products, key=lambda x: x["qty"], reverse=True)

    top_limit = 20
    top_products = all_products_sorted[:top_limit]
    if len(all_products_sorted) > top_limit:
        others_sum_qty = sum(p["qty"] for p in all_products_sorted[top_limit:])
        others_sum_revenue = sum(p["revenue"] for p in all_products_sorted[top_limit:])
        others_sum_profit = sum(p["profit"] for p in all_products_sorted[top_limit:])
        top_products.append({
            "name": f"Others ({len(all_products_sorted) - top_limit})",
            "qty": int(others_sum_qty),
            "revenue": float(round(others_sum_revenue,2)),
            "profit": float(round(others_sum_profit,2))
        })

    product_names = [p["name"] for p in top_products]
    quantities = [int(p["qty"]) for p in top_products]
    revenues = [float(round(p["revenue"], 2)) for p in top_products]
    profits = [float(round(p["profit"], 2)) for p in top_products]

    top_sales = json.dumps([
        {"name": p["name"], "profit": float(round(p["profit"], 2)), 
        "revenue": float(round(p["revenue"], 2)), "qty": int(p["qty"])}
        for p in top_products
    ])


    # --- Monthly sales chart (last 6 months) ---
    today = datetime.utcnow()
    months, sales_per_month = [], []
    for i in range(5, -1, -1):
        year = today.year
        month = today.month - i
        while month <= 0:
            month += 12
            year -= 1
        months.append(f"{month_abbr[month]} {year}")
        sales_per_month.append(0.0)

    def month_index_for(dt):
        label = f"{month_abbr[dt.month]} {dt.year}"
        try:
            return months.index(label)
        except ValueError:
            return None

    for s in sales_rows:
        try:
            sold_dt = datetime.fromisoformat(s.sold_at)
        except Exception:
            continue
        idx = month_index_for(sold_dt)
        if idx is not None:
            sales_per_month[idx] += float(s.total or 0.0)

    total_quantity_sold = int(total_quantity_sold)
    total_sales = float(total_revenue)
    total_profit = float(total_income)

    monthly_sales = {
        "month": today.strftime("%B"),
        "total_income": round(total_income, 2),
        "total_sales": round(total_sales, 2),
    }

    return render_template(
        "admin_dashboard.html",
        products=products,
        orders=orders,
        total_products=total_products,
        total_orders=total_orders,
        pending_orders=pending_orders,
        completed_orders=completed_orders,
        canceled_orders=canceled_orders,
        sales_data=sales_data,
        product_names=product_names,
        quantities=quantities,
        revenues=revenues,
        profits=profits,
        total_income=total_income,
        total_sales=total_sales,
        total_profit=total_profit,
        total_quantity_sold=total_quantity_sold,
        months=months,
        sales_per_month=sales_per_month,
        top_products=top_products,
        top_sales=top_sales,
        monthly_sales=monthly_sales,
    )



@app.route("/admin/products" , methods=["GET", "POST"])
@login_required
@admin_required
def admin_products():
    products = Product.query.order_by(Product.name).all()
    return render_template("admin_products.html", products=products)

@app.route("/admin/products/add", methods=["GET","POST"])
@login_required
@admin_required
def admin_add_product():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        desc = request.form.get("description","").strip()
        try:
            price = float(request.form.get("price") or 0)
            cost_price = float(request.form.get("cost_price") or 0)
            stock = int(request.form.get("stock") or 0)
        except ValueError:
            flash("Invalid price or stock.", "danger")
            return redirect(url_for("admin_add_product"))

        file = request.files.get("image")
        filename = "default.png"
        if file and file.filename != "" and allowed_file(file.filename):
            safe = secure_filename(file.filename)
            filename = f"{int(datetime.utcnow().timestamp())}_{safe}"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            try:
                file.save(filepath)
            except Exception:
                filename = "default.png"

        p = Product(name=name, description=desc, price=price, cost_price=cost_price, stock=stock, image=filename)
        db.session.add(p)
        db.session.commit()
        log_action(current_user.username, "add_product", f"product_id={p.id} name={p.name}")
        flash("Product added.", "success")
        return redirect(url_for("admin_products"))
    return render_template("admin_product_form.html", action="Add", product=None)

@app.route("/admin/products/edit/<int:pid>", methods=["GET","POST"])
@login_required
@admin_required
def admin_edit_product(pid):
    p = db.session.get(Product, pid)
    if not p:
        abort(404)
    if request.method == "POST":
        p.name = request.form.get("name","").strip()
        p.description = request.form.get("description","").strip()
        try:
            p.price = float(request.form.get("price") or 0)
            p.cost_price = float(request.form.get("cost_price") or 0)
            p.stock = int(request.form.get("stock") or 0)
        except ValueError:
            flash("Invalid price or stock.", "danger")
            return redirect(url_for("admin_edit_product", pid=pid))

        file = request.files.get("image")
        if file and file.filename != "" and allowed_file(file.filename):
            safe = secure_filename(file.filename)
            filename = f"{int(datetime.utcnow().timestamp())}_{safe}"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            try:
                file.save(filepath)
                if p.image and p.image != "default.png":
                    old = os.path.join(app.config["UPLOAD_FOLDER"], p.image)
                    if os.path.exists(old):
                        os.remove(old)
                p.image = filename
            except Exception:
                flash("Failed to save new image.", "warning")
        db.session.commit()
        log_action(current_user.username, "edit_product", f"product_id={p.id}")
        flash("Product updated.", "success")
        return redirect(url_for("admin_products"))
    return render_template("admin_product_form.html", action="Edit", product=p)

@app.route("/admin/products/delete/<int:pid>", methods=["POST"])
@login_required
@admin_required
def admin_delete_product(pid):
    p = db.session.get(Product, pid)
    if not p:
        abort(404)
    try:
        if p.image and p.image != "default.png":
            fp = os.path.join(app.config["UPLOAD_FOLDER"], p.image)
            if os.path.exists(fp):
                os.remove(fp)
    except Exception:
        pass
    db.session.delete(p)
    db.session.commit()
    log_action(current_user.username, "delete_product", f"product_id={pid} name={p.name}")
    flash("Product deleted.", "info")
    return redirect(url_for("admin_products"))

@app.route("/admin/orders")
@login_required
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin_orders.html", orders=orders)

@app.route("/admin/orders/<int:order_id>")
@login_required
@admin_required
def admin_order_detail(order_id):
    order = db.session.get(Order, order_id)
    if not order:
        abort(404)
    items = OrderItem.query.filter_by(order_id=order.id).all()
    return render_template("admin_order_detail.html", order=order, items=items)

@app.route("/admin/orders/<int:order_id>/mark_paid", methods=["POST"])
@login_required
@admin_required
def admin_mark_paid(order_id):
    order = db.session.get(Order, order_id)
    if not order:
        abort(404)
    if order.status == "paid":
        flash("Order already paid.", "info")
        return redirect(url_for("admin_order_detail", order_id=order_id))

    items = OrderItem.query.filter_by(order_id=order.id).all()
    # check stock
    for it in items:
        p = db.session.get(Product, it.product_id)
        if not p or p.stock < it.quantity:
            flash(f"Not enough stock for {it.product_name}.", "danger")
            return redirect(url_for("admin_order_detail", order_id=order_id))

    # decrement stock and record sales
    for it in items:
        p = db.session.get(Product, it.product_id)
        p.stock -= it.quantity
        s = Sale(product_id=p.id, quantity=it.quantity, total=it.total)
        db.session.add(s)
    order.status = "paid"
    db.session.commit()
    log_action(current_user.username, "mark_paid", f"order_id={order.id}")
    flash("Order marked as paid. Stock updated.", "success")
    return redirect(url_for("admin_order_detail", order_id=order_id))

@app.route("/admin/audit")
@login_required
@admin_required
def admin_audit():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template("admin_audit.html", logs=logs)

@app.route("/admin/sales/export")
@login_required
@admin_required
def admin_export_sales():
    sales = Sale.query.order_by(Sale.sold_at.desc()).all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Product ID","Quantity","Total","Sold At"])
    for s in sales:
        cw.writerow([s.id, s.product_id, s.quantity, f"{s.total:.2f}", s.sold_at])
    mem = io.BytesIO()
    mem.write(si.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True,
                     download_name=f"sales_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.csv")

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)
