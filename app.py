import os, csv, io, secrets, re
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template_string, flash, abort, make_response
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from db import get_conn, init_db
from security import hash_password, verify_password, login_required, roles_required, business_id, audit

app = Flask(__name__)
secret = os.environ.get("POS_SECRET_KEY")
if not secret:
    raise RuntimeError("POS_SECRET_KEY must be set in the environment.")
app.config.update(
    SECRET_KEY=secret,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
    WTF_CSRF_TIME_LIMIT=3600,
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)
# Only trust one proxy hop on Render. Do not expose this app behind untrusted proxies.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[],
                  storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"))

BASE = """
<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure POS</title></head><body>
<h2>Secure POS & Loyalty</h2>
{% with messages = get_flashed_messages() %}{% for m in messages %}<p>{{m}}</p>{% endfor %}{% endwith %}
{% if session.get('user_id') %}<p>Signed in as {{session.get('username')}} ({{session.get('role')}}) |
<form method="post" action="{{url_for('logout')}}" style="display:inline">{{csrf_token()}}<button>Logout</button></form></p>{% endif %}
{{ body|safe }}
</body></html>
"""

def page(body, **ctx):
    from flask_wtf.csrf import generate_csrf
    # Body is intentionally rendered as a fragment; replace only our CSRF marker
    # with a generated hidden input. User/database values must be HTML-escaped.
    csrf_input = '<input type="hidden" name="csrf_token" value="' + generate_csrf() + '">'
    body = body.replace("{{csrf_token()}}", csrf_input)
    return render_template_string(BASE, body=body, csrf_token=generate_csrf, **ctx)

def money(value):
    return Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.errorhandler(403)
def forbidden(_):
    return page("<h3>Access denied.</h3>"), 403

@app.errorhandler(413)
def too_large(_):
    return page("<h3>Upload too large.</h3>"), 413

@app.get("/")
def home():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    role = session.get("role")
    links = []
    if role in ("superadmin", "platform_admin"):
        links.append('<p><a href="/businesses">Manage businesses</a></p>')
    if role in ("admin", "billing_user", "platform_admin", "superadmin"):
        links += ['<p><a href="/products">Products / Stock</a></p>',
                  '<p><a href="/billing">New bill</a></p>',
                  '<p><a href="/reports.csv">Download sales CSV</a></p>']
    if role == "admin":
        links.append('<p><a href="/staff">Create billing user</a></p>')
    return page("".join(links) or "<p>Customer account</p>")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()[:120]
        password = request.form.get("password") or ""
        with get_conn() as conn:
            # Username is globally unambiguous for platform users; business username scoped by business.
            rows = conn.execute(
                """SELECT id,business_id,username,password_hash,role,active,must_change_password
                   FROM users WHERE lower(username)=lower(%s) AND active=TRUE
                   ORDER BY id LIMIT 2""", (username,)
            ).fetchall()
        # Do not allow ambiguous username login across businesses.
        if len(rows) == 1 and verify_password(rows[0]["password_hash"], password):
            u = rows[0]
            session.clear()
            session["user_id"] = u["id"]
            session["business_id"] = u["business_id"]
            session["username"] = u["username"]
            session["role"] = u["role"]
            session.permanent = True
            with get_conn() as conn:
                audit(conn, "login_success", u["business_id"], {})
                conn.commit()
            return redirect(url_for("change_password") if u["must_change_password"] else url_for("home"))
        with get_conn() as conn:
            audit(conn, "login_failed", None, {"username": username})
            conn.commit()
        flash("Invalid username or password.")
    return page("""
      <form method="post">{{csrf_token()}}
      <p><input name="username" maxlength="120" autocomplete="username" required placeholder="Username"></p>
      <p><input type="password" name="password" autocomplete="current-password" required placeholder="Password"></p>
      <button>Login</button></form>
    """)

@app.post("/logout")
@login_required
def logout():
    with get_conn() as conn:
        audit(conn, "logout", session.get("business_id"), {})
        conn.commit()
    session.clear()
    return redirect(url_for("login"))

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if password != confirm:
            flash("Passwords do not match.")
        else:
            try:
                new_hash = hash_password(password)
            except ValueError as e:
                flash(str(e))
            else:
                with get_conn() as conn:
                    conn.execute("UPDATE users SET password_hash=%s,must_change_password=FALSE WHERE id=%s",
                                 (new_hash, session["user_id"]))
                    audit(conn, "password_changed", session.get("business_id"), {})
                    conn.commit()
                flash("Password updated.")
                return redirect(url_for("home"))
    return page("""<form method="post">{{csrf_token()}}
    <p><input type="password" name="password" minlength="12" required placeholder="New password"></p>
    <p><input type="password" name="confirm" minlength="12" required placeholder="Confirm password"></p>
    <button>Change password</button></form>""")

@app.route("/businesses", methods=["GET", "POST"])
@roles_required("superadmin", "platform_admin")
def businesses():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        kind = (request.form.get("business_type") or "general").strip()
        username = (request.form.get("admin_username") or "").strip()
        password = request.form.get("admin_password") or ""
        if not name or len(name) > 150 or not re.fullmatch(r"[A-Za-z0-9_.-]{3,60}", username):
            flash("Enter a valid business name and admin username.")
        else:
            try:
                ph = hash_password(password)
            except ValueError as e:
                flash(str(e))
            else:
                with get_conn() as conn:
                    with conn.transaction():
                        b = conn.execute("INSERT INTO businesses(name,business_type) VALUES(%s,%s) RETURNING id",
                                         (name, kind)).fetchone()
                        conn.execute("""INSERT INTO users(business_id,username,password_hash,role,must_change_password)
                                        VALUES(%s,%s,%s,'admin',TRUE)""", (b["id"], username, ph))
                        audit(conn, "business_created", b["id"], {"business_name": name})
                flash("Business and admin created. Admin must change password at first login.")
    with get_conn() as conn:
        rows = conn.execute("SELECT id,name,business_type,active,created_at FROM businesses ORDER BY id DESC").fetchall()
    items = "".join(f"<li>#{r['id']} — {r['name']} ({r['business_type']}) — {'active' if r['active'] else 'inactive'}</li>" for r in rows)
    return page("""
      <h3>Create business</h3><form method="post">{{csrf_token()}}
      <p><input name="name" maxlength="150" required placeholder="Business name"></p>
      <p><input name="business_type" maxlength="80" placeholder="Business type"></p>
      <p><input name="admin_username" maxlength="60" required placeholder="Business admin username"></p>
      <p><input type="password" name="admin_password" minlength="12" required placeholder="Temporary password (12+ chars)"></p>
      <button>Create</button></form><h3>Businesses</h3><ul>""" + items + "</ul>")

@app.route("/staff", methods=["GET", "POST"])
@roles_required("admin")
def staff():
    bid = business_id()
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        try:
            ph = hash_password(password)
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,60}", username):
                raise ValueError("Username must be 3-60 letters, numbers, dot, underscore or hyphen.")
        except ValueError as e:
            flash(str(e))
        else:
            try:
                with get_conn() as conn:
                    conn.execute("""INSERT INTO users(business_id,username,password_hash,role,must_change_password)
                                    VALUES(%s,%s,%s,'billing_user',TRUE)""", (bid, username, ph))
                    audit(conn, "billing_user_created", bid, {"username": username})
                    conn.commit()
                flash("Billing user created; change password at first login.")
            except Exception:
                flash("Could not create user. Check that username is unique for this business.")
    return page("""<h3>Create billing user</h3><form method="post">{{csrf_token()}}
      <p><input name="username" maxlength="60" required placeholder="Username"></p>
      <p><input type="password" name="password" minlength="12" required placeholder="Temporary password"></p>
      <button>Create user</button></form>""")

@app.route("/products", methods=["GET", "POST"])
@roles_required("superadmin", "platform_admin", "admin", "billing_user")
def products():
    bid = business_id()
    if request.method == "POST":
        if session["role"] not in ("admin", "superadmin", "platform_admin"):
            abort(403)
        name = (request.form.get("name") or "").strip()
        sku = (request.form.get("sku") or "").strip() or None
        try:
            price = money(request.form.get("price", ""))
            stock = Decimal(request.form.get("stock", "0"))
            gst = Decimal(request.form.get("gst_rate", "0"))
            if not name or len(name) > 160 or price < 0 or stock < 0 or gst < 0 or gst > 100:
                raise ValueError()
        except (InvalidOperation, ValueError):
            flash("Invalid product values.")
        else:
            with get_conn() as conn:
                try:
                    conn.execute("""INSERT INTO products(business_id,name,sku,price,stock,gst_rate)
                                    VALUES(%s,%s,%s,%s,%s,%s)""", (bid,name,sku,price,stock,gst))
                    audit(conn, "product_created", bid, {"name": name})
                    conn.commit()
                    flash("Product added.")
                except Exception:
                    conn.rollback()
                    flash("Product could not be saved; check duplicate SKU.")
    with get_conn() as conn:
        rows = conn.execute("""SELECT id,name,sku,price,stock,gst_rate FROM products
                               WHERE business_id=%s AND active=TRUE ORDER BY name""", (bid,)).fetchall()
    body = """<h3>Add product</h3><form method="post">{{csrf_token()}}
      <p><input name="name" maxlength="160" required placeholder="Product name"></p>
      <p><input name="sku" maxlength="80" placeholder="SKU (optional)"></p>
      <p><input name="price" type="number" step="0.01" min="0" required placeholder="Price"></p>
      <p><input name="stock" type="number" step="0.001" min="0" value="0" required placeholder="Stock"></p>
      <p><input name="gst_rate" type="number" step="0.01" min="0" max="100" value="0" required placeholder="GST %"></p>
      <button>Add product</button></form><h3>Products</h3><table border="1"><tr><th>Name</th><th>SKU</th><th>Price</th><th>Stock</th><th>GST%</th></tr>"""
    import html
    body += "".join(
        "<tr><td>" + html.escape(str(r["name"])) + "</td><td>" +
        html.escape(str(r["sku"] or "")) + "</td><td>" +
        html.escape(str(r["price"])) + "</td><td>" +
        html.escape(str(r["stock"])) + "</td><td>" +
        html.escape(str(r["gst_rate"])) + "</td></tr>" for r in rows
    )
    body += "</table>"
    return page(body)

@app.route("/billing", methods=["GET", "POST"])
@roles_required("admin", "billing_user")
@limiter.limit("30 per minute", methods=["POST"])
def billing():
    bid = business_id()
    if request.method == "POST":
        idem = (request.form.get("idempotency_key") or "").strip()
        customer_raw = (request.form.get("customer_id") or "").strip()
        product_raw = (request.form.get("product_id") or "").strip()
        qty_raw = (request.form.get("quantity") or "").strip()
        if not idem or len(idem) > 100:
            flash("Invalid checkout token. Refresh the page and retry.")
            return redirect(url_for("billing"))
        try:
            pid = int(product_raw)
            qty = Decimal(qty_raw)
            customer_id = int(customer_raw) if customer_raw else None
            if qty <= 0 or qty > 100000:
                raise ValueError()
        except (ValueError, InvalidOperation):
            flash("Invalid product, customer, or quantity.")
            return redirect(url_for("billing"))
        try:
            with get_conn() as conn:
                with conn.transaction():
                    prior = conn.execute("SELECT id,total FROM sales WHERE business_id=%s AND idempotency_key=%s",
                                         (bid, idem)).fetchone()
                    if prior:
                        flash(f"Sale already recorded as bill #{prior['id']}.")
                        return redirect(url_for("billing"))
                    product = conn.execute("""SELECT id,name,price,stock,gst_rate FROM products
                                              WHERE business_id=%s AND id=%s AND active=TRUE FOR UPDATE""",
                                           (bid,pid)).fetchone()
                    if not product:
                        raise ValueError("Product not found.")
                    if product["stock"] < qty:
                        raise ValueError("Insufficient stock.")
                    if customer_id:
                        cust = conn.execute("""SELECT id FROM users WHERE id=%s AND business_id=%s
                                               AND role='customer' AND active=TRUE""",
                                            (customer_id,bid)).fetchone()
                        if not cust:
                            raise ValueError("Customer not found in this business.")
                    line_sub = money(Decimal(product["price"]) * qty)
                    line_gst = money(line_sub * Decimal(product["gst_rate"]) / Decimal("100"))
                    total = money(line_sub + line_gst)
                    sale = conn.execute("""INSERT INTO sales(business_id,customer_id,created_by,idempotency_key,
                                           subtotal,gst_total,total) VALUES(%s,%s,%s,%s,%s,%s,%s)
                                           RETURNING id""",
                                        (bid,customer_id,session["user_id"],idem,line_sub,line_gst,total)).fetchone()
                    conn.execute("""INSERT INTO sale_items(sale_id,product_id,product_name,quantity,unit_price,
                                    gst_rate,line_subtotal,line_gst,line_total)
                                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                                 (sale["id"],pid,product["name"],qty,product["price"],product["gst_rate"],line_sub,line_gst,total))
                    conn.execute("UPDATE products SET stock=stock-%s WHERE business_id=%s AND id=%s",
                                 (qty,bid,pid))
                    points = int(total // Decimal("100")) * 10
                    if customer_id and points:
                        conn.execute("""INSERT INTO customer_loyalty(business_id,customer_id,points)
                                        VALUES(%s,%s,%s) ON CONFLICT(business_id,customer_id)
                                        DO UPDATE SET points=customer_loyalty.points+EXCLUDED.points""",
                                     (bid,customer_id,points))
                        conn.execute("UPDATE sales SET points_awarded=%s WHERE id=%s", (points,sale["id"]))
                    audit(conn, "sale_created", bid, {"sale_id": sale["id"], "total": str(total), "points": points})
                flash(f"Bill #{sale['id']} created. Total ₹{total}; points awarded: {points}.")
        except ValueError as e:
            flash(str(e))
        except Exception:
            app.logger.exception("Billing failed")
            flash("Bill could not be completed. Check stock and retry; duplicate submissions are protected.")
        return redirect(url_for("billing"))
    with get_conn() as conn:
        products_rows = conn.execute("SELECT id,name,price,stock FROM products WHERE business_id=%s AND active=TRUE ORDER BY name", (bid,)).fetchall()
        customers = conn.execute("SELECT id,username,phone FROM users WHERE business_id=%s AND role='customer' AND active=TRUE ORDER BY username", (bid,)).fetchall()
        recent = conn.execute("SELECT id,total,created_at FROM sales WHERE business_id=%s ORDER BY id DESC LIMIT 20", (bid,)).fetchall()
    import html
    product_options = "".join(f'<option value="{r["id"]}">{html.escape(r["name"])} — ₹{r["price"]} (stock {r["stock"]})</option>' for r in products_rows)
    customer_options = '<option value="">Walk-in customer</option>' + "".join(f'<option value="{r["id"]}">{html.escape(r["username"])} {html.escape(r["phone"] or "")}</option>' for r in customers)
    recent_html = "".join(f'<li>Bill #{r["id"]}: ₹{r["total"]} — {r["created_at"]}</li>' for r in recent)
    token = secrets.token_urlsafe(24)
    session["checkout_token"] = token
    return page(f"""<h3>Create bill</h3><form method="post">{{{{csrf_token()}}}}
      <input type="hidden" name="idempotency_key" value="{token}">
      <p><select name="product_id" required>{product_options}</select></p>
      <p><input type="number" name="quantity" min="0.001" step="0.001" value="1" required></p>
      <p><select name="customer_id">{customer_options}</select></p>
      <button>Create bill</button></form><h3>Recent bills</h3><ul>{recent_html}</ul>""")

@app.get("/reports.csv")
@roles_required("superadmin", "platform_admin", "admin", "billing_user")
def reports_csv():
    bid = business_id()
    with get_conn() as conn:
        rows = conn.execute("""SELECT id,created_at,subtotal,gst_total,total,points_awarded
                               FROM sales WHERE business_id=%s ORDER BY id DESC LIMIT 10000""", (bid,)).fetchall()
        audit(conn, "sales_csv_exported", bid, {"row_count": len(rows)})
        conn.commit()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Bill ID","Created At","Subtotal","GST","Total","Points Awarded"])
    for r in rows:
        w.writerow([r["id"],r["created_at"],r["subtotal"],r["gst_total"],r["total"],r["points_awarded"]])
    response = make_response("\\ufeff" + out.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=sales_report.csv"
    return response

def bootstrap():
    init_db()
    username = os.environ.get("INITIAL_SUPERADMIN_USERNAME")
    password = os.environ.get("INITIAL_SUPERADMIN_PASSWORD")
    if not username or not password:
        app.logger.warning("No initial superadmin credentials configured; existing users can still sign in.")
        return
    with get_conn() as conn:
        found = conn.execute("SELECT id FROM users WHERE role='superadmin' LIMIT 1").fetchone()
        if not found:
            ph = hash_password(password)
            conn.execute("""INSERT INTO users(business_id,username,password_hash,role)
                            VALUES(NULL,%s,%s,'superadmin')""", (username,ph))
            audit(conn, "initial_superadmin_created", None, {"username": username})
            conn.commit()

bootstrap()

if __name__ == "__main__":
    app.run(debug=False)
