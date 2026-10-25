from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, inspect, text
from datetime import date, datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import random
import json
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quick_cafe.db'
app.config['SECRET_KEY'] = 'your_secret_key'   # change this to a long random string
db = SQLAlchemy(app)


# ======================= MODELS =======================
class Role(db.Model):
    __tablename__ = 'role'
    role_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

class Menu(db.Model):
    __tablename__ = 'menu'
    item_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

class Order(db.Model):
    __tablename__ = 'order'
    order_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    pickup_slot = db.Column(db.String(10), nullable=False)
    order_status = db.Column(db.Boolean, nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('menu.item_id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

class Payment(db.Model):
    __tablename__ = 'payment'
    p_id = db.Column(db.Integer, primary_key=True)
    Payment_amount = db.Column(db.Float, nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    payment_status = db.Column(db.String(20), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('menu.item_id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

class Digital_token(db.Model):
    __tablename__ = 'digital_token'
    token_id = db.Column(db.Integer, primary_key=True)
    token_number = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    is_available = db.Column(db.Boolean, default=True, nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('menu.item_id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.order_id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    # kitchen workflow: Pending -> Preparing -> Ready -> Completed
    kitchen_status = db.Column(db.String(20), nullable=False, default='Pending', server_default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.now)


# ======================= ADMIN AUTH =======================
def current_admin():
    """Return the logged-in admin User, or None."""
    uid = session.get('user_id')
    if not uid:
        return None
    user = db.session.get(User, uid)
    if not user or user.is_deleted:
        return None
    role = db.session.get(Role, user.role_id)
    if role and role.name.lower() == 'admin':
        return user
    return None


# role name (lower-case)  ->  endpoint of that role's own dashboard
ROLE_HOME = {
    'admin': 'admin',
    'cashier': 'cashier',
    'chasier': 'cashier',   # old spelling kept so existing data still works
    'staff': 'staff',
}


# payment_status values that count as money received
#   'Completed' = online/QR payment, 'Digital' = QR at counter, 'Cash' = cash at counter
PAID_STATUSES = ('Completed', 'Digital', 'Cash')
DIGITAL_STATUSES = ('Completed', 'Digital')


def role_group_of_name(name):
    return ROLE_HOME.get((name or '').lower())


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    user = db.session.get(User, uid)
    return None if (not user or user.is_deleted) else user


def role_group(user):
    """'admin' / 'cashier' / 'staff' / None"""
    role = db.session.get(Role, user.role_id) if user else None
    return ROLE_HOME.get(role.name.lower()) if role else None


def home_for(user):
    """URL of the dashboard this user belongs to."""
    return url_for(role_group(user) or 'dashboard')


# URL prefix -> which role group owns it
PROTECTED_PREFIXES = {'/admin': 'admin', '/cashier': 'cashier', '/staff': 'staff'}


def safe_next(url):
    """Only allow local paths like /admin (blocks http://evil.com and //evil.com)."""
    if url and url.startswith('/') and not url.startswith('//') and not url.startswith('/login'):
        return url
    return None


def next_allowed(user, path):
    """Can this user open that path? (admin can open everything)"""
    group = role_group(user)
    for prefix, owner in PROTECTED_PREFIXES.items():
        if path == prefix or path.startswith(prefix + '/'):
            return group in (owner, 'admin')
    return True


def deny_and_ask_login(label):
    """Wrong role (or not logged in): log out and ask for the right account."""
    if 'user_id' in session:
        session.clear()
        flash(f"That page is for {label} only. Please log in with a {label} account.", "warning")
    else:
        flash(f"Please log in as {label} to open that page.", "warning")
    if request.method == 'GET':
        return redirect(url_for('login', next=request.full_path.rstrip('?')))
    return redirect(url_for('login'))       # POST routes can't be 'returned to'


def role_required(*allowed):
    """Allow only the given role groups (admin is always allowed)."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or role_group(user) not in set(allowed) | {'admin'}:
                return deny_and_ask_login(' / '.join(allowed))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or role_group(user) != 'admin':
            return deny_and_ask_login('admin')
        return f(*args, **kwargs)
    return wrapper


# ======================= PUBLIC PAGES =======================
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/menu')
def menu():
    return render_template('menu.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/order')
def order():
    order = session.get("current_order", [])
    total_amount = sum(item["price"] * item["quantity"] for item in order)
    return render_template('order.html', order=order, total_amount=total_amount)


@app.route("/update_order")
def update_order():
    item_name = request.args.get("item_name")
    change = int(request.args.get("change", 0))
    order = session.get("current_order", [])

    for item in order:
        if item["name"] == item_name:
            item["quantity"] += change
            if item["quantity"] <= 0:
                order.remove(item)
            break

    session["current_order"] = order
    return redirect(url_for("order"))


@app.route("/add_to_order")
def add_to_order():
    item_name = request.args.get('item')
    price = float(request.args.get('price'))

    order = session.get('current_order', [])
    item_found = False
    for item in order:
        if item['name'] == item_name:
            item['quantity'] += 1
            item_found = True
            break
    if not item_found:
        order.append({'name': item_name, 'price': price, 'quantity': 1})

    session['current_order'] = order
    session.modified = True

    flash(f"{item_name} has been added to your Order Items.", "info")
    return redirect(request.referrer or url_for('menu'))


@app.route('/place_order', methods=['POST'])
def place_order():
    customer_name = request.form.get('customer_name')
    order_items = session.get("current_order", [])

    if not order_items:
        flash("Your order is empty!", "warning")
        return redirect(url_for('order'))

    total_amount = sum(item["price"] * item["quantity"] for item in order_items)
    session['pending_order'] = {
        'customer_name': customer_name,
        'total_amount': total_amount,
        'items': order_items
    }
    return redirect(url_for('payment_page'))


@app.route('/payment')
def payment_page():
    pending_order = session.get('pending_order')
    if not pending_order:
        flash("No pending order found.", "warning")
        return redirect(url_for('order'))
    return render_template('payment.html', order=pending_order)


@app.route('/confirm_payment', methods=['POST'])
def confirm_payment():
    pending_order = session.get('pending_order')
    if not pending_order:
        flash("No active order to process.", "danger")
        return redirect(url_for('order'))

    while True:
        generated_token_number = f"TKN-{random.randint(1000, 9999)}"
        if not Digital_token.query.filter_by(token_number=generated_token_number).first():
            break

    with db.session.no_autoflush:
        for item in pending_order['items']:
            menu_item = Menu.query.filter_by(name=item['name']).first()
            item_id = menu_item.item_id if menu_item else 1

            new_order = Order(
                name=pending_order['customer_name'],
                total_amount=item['price'] * item['quantity'],
                pickup_slot="10:00 AM",
                order_status=True,
                item_id=item_id,
                is_deleted=False
            )
            db.session.add(new_order)
            db.session.flush()

            db.session.add(Payment(
                Payment_amount=item['price'] * item['quantity'],
                date_time=datetime.now(),
                payment_status="Completed",
                item_id=item_id,
                is_deleted=False
            ))

            db.session.add(Digital_token(
                token_number=generated_token_number,
                name=item['name'],
                price=item['price'],
                quantity=item['quantity'],
                is_available=True,
                item_id=item_id,
                order_id=new_order.order_id,
                is_deleted=False
            ))

    db.session.commit()
    session.pop('current_order', None)
    session.pop('pending_order', None)

    flash("Payment successful! Token generated.", "success")
    return redirect(url_for('view_token', token_id=generated_token_number))


@app.route('/digital_token/<token_id>')
def view_token(token_id):
    tokens = Digital_token.query.filter_by(token_number=token_id).all()
    if not tokens:
        flash("Token not found.", "danger")
        return redirect(url_for('home'))
    return render_template('token.html', tokens=tokens, token_number=token_id)


# ======================= ADMIN DASHBOARD =======================
@app.route('/admin')
@admin_required
def admin():
    admin_user = current_admin()
    today_start = datetime.combine(date.today(), datetime.min.time())

    today_sales = db.session.query(func.coalesce(func.sum(Payment.Payment_amount), 0)) \
        .filter(Payment.date_time >= today_start,
                Payment.payment_status.in_(PAID_STATUSES),
                Payment.is_deleted == False).scalar()
    orders_served = Order.query.filter_by(is_deleted=False).count()
    menu_count = Menu.query.filter_by(is_deleted=False).count()
    staff_count = User.query.filter_by(is_deleted=False).count()

    menu_items = Menu.query.filter_by(is_deleted=False).order_by(Menu.item_id).all()

    staff = db.session.query(User, Role).join(Role, User.role_id == Role.role_id) \
        .filter(User.is_deleted == False).order_by(User.user_id).all()

    week_start = datetime.combine(date.today() - timedelta(days=6), datetime.min.time())
    daily_sales = db.session.query(
            func.date(Payment.date_time),
            func.sum(Payment.Payment_amount),
            func.count(Payment.p_id)) \
        .filter(Payment.date_time >= week_start, Payment.is_deleted == False) \
        .group_by(func.date(Payment.date_time)) \
        .order_by(func.date(Payment.date_time).desc()).all()

    top_items = db.session.query(Menu.name, func.sum(Payment.Payment_amount), func.count(Payment.p_id)) \
        .join(Menu, Payment.item_id == Menu.item_id) \
        .filter(Payment.is_deleted == False) \
        .group_by(Menu.name) \
        .order_by(func.sum(Payment.Payment_amount).desc()).limit(5).all()

    return render_template('admin.html',
        admin_user=admin_user,
        today_sales=today_sales, orders_served=orders_served,
        menu_count=menu_count, staff_count=staff_count,
        menu_items=menu_items, staff=staff,
        daily_sales=daily_sales, top_items=top_items)


@app.route('/admin/menu/add', methods=['POST'])
@admin_required
def admin_add_menu():
    name = request.form.get('name', '').strip()
    try:
        price = float(request.form.get('price', 0))
    except ValueError:
        price = -1
    if not name or price <= 0:
        flash("Enter a valid item name and price.", "danger")
        return redirect(url_for('admin') + '#managemenu')
    db.session.add(Menu(name=name, price=price,
                        is_available=bool(request.form.get('is_available')),
                        is_deleted=False))
    db.session.commit()
    flash(f"'{name}' added to the menu.", "success")
    return redirect(url_for('admin') + '#managemenu')


@app.route('/admin/menu/<int:item_id>/edit', methods=['POST'])
@admin_required
def admin_edit_menu(item_id):
    item = db.get_or_404(Menu, item_id)
    name = request.form.get('name', '').strip()
    try:
        price = float(request.form.get('price', 0))
    except ValueError:
        price = -1
    if not name or price <= 0:
        flash("Enter a valid item name and price.", "danger")
    else:
        item.name = name
        item.price = price
        item.is_available = bool(request.form.get('is_available'))
        db.session.commit()
        flash(f"'{name}' updated.", "success")
    return redirect(url_for('admin') + '#managemenu')


@app.route('/admin/menu/<int:item_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_menu(item_id):
    item = db.get_or_404(Menu, item_id)
    item.is_available = not item.is_available
    db.session.commit()
    flash(f"'{item.name}' marked {'Available' if item.is_available else 'Out of Stock'}.", "info")
    return redirect(url_for('admin') + '#managemenu')


@app.route('/admin/menu/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_menu(item_id):
    item = db.get_or_404(Menu, item_id)
    item.is_deleted = True
    db.session.commit()
    flash(f"'{item.name}' removed from the menu.", "warning")
    return redirect(url_for('admin') + '#managemenu')


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        flash("You cannot remove your own account.", "danger")
    else:
        user = db.get_or_404(User, user_id)
        user.is_deleted = True
        db.session.commit()
        flash(f"User '{user.name}' removed.", "warning")
    return redirect(url_for('admin') + '#staffrole')


# ======================= OTHER DASHBOARDS =======================
# ======================= CASHIER =======================
def latest_token_numbers(limit):
    rows = db.session.query(Digital_token.token_number) \
        .filter(Digital_token.is_deleted == False) \
        .group_by(Digital_token.token_number) \
        .order_by(func.max(Digital_token.token_id).desc()).limit(limit).all()
    return [r[0] for r in rows]


def build_token_groups(numbers):
    """Group Digital_token rows by token number -> list of dicts (newest first)."""
    if not numbers:
        return []
    rows = db.session.query(Digital_token, Order.name) \
        .join(Order, Digital_token.order_id == Order.order_id) \
        .filter(Digital_token.token_number.in_(numbers), Digital_token.is_deleted == False) \
        .order_by(Digital_token.token_id).all()
    groups = {}
    for t, customer in rows:
        g = groups.setdefault(t.token_number, {
            'number': t.token_number, 'customer': customer,
            'lines': [], 'total': 0.0, 'served': True, 'id': 0})
        g['lines'].append(t)
        g['total'] += t.price * t.quantity
        g['id'] = max(g['id'], t.token_id)
        if t.is_available:
            g['served'] = False
    return sorted(groups.values(), key=lambda g: -g['id'])


@app.route('/cashier')
@role_required('cashier')
def cashier():
    user = current_user()
    today_start = datetime.combine(date.today(), datetime.min.time())

    def paid_today(statuses):
        return db.session.query(func.coalesce(func.sum(Payment.Payment_amount), 0)) \
            .filter(Payment.date_time >= today_start,
                    Payment.payment_status.in_(statuses),
                    Payment.is_deleted == False).scalar()

    cash_today = paid_today(('Cash',))
    digital_today = paid_today(DIGITAL_STATUSES)
    items_today = Payment.query.filter(Payment.date_time >= today_start,
                                       Payment.payment_status.in_(PAID_STATUSES),
                                       Payment.is_deleted == False).count()

    menu_items = Menu.query.filter_by(is_deleted=False, is_available=True) \
        .order_by(Menu.name).all()
    history = build_token_groups(latest_token_numbers(50))

    verify_q = request.args.get('verify', '').strip().upper()
    verified = None
    if verify_q:
        found = build_token_groups([verify_q])
        verified = found[0] if found else False     # False = searched but not found

    return render_template('cashier.html', cashier_user=user,
        menu_items=menu_items, recent=history[:6], history=history,
        cash_today=cash_today, digital_today=digital_today, items_today=items_today,
        verify_q=verify_q, verified=verified)


@app.route('/cashier/create_order', methods=['POST'])
@role_required('cashier')
def cashier_create_order():
    customer = request.form.get('customer', '').strip()
    pay_mode = 'Cash' if request.form.get('pay_mode') == 'cash' else 'Digital'
    pickup = request.form.get('pickup', '').strip()
    pickup = pickup if re.fullmatch(r'\d{2}:\d{2}', pickup) else 'Now'

    # --- parse + validate the cart (prices always come from the DB, never the browser) ---
    try:
        raw = json.loads(request.form.get('items_json', '[]'))
        wanted = {}
        for r in raw:
            iid, qty = int(r['item_id']), int(r['qty'])
            if not 1 <= qty <= 50:
                raise ValueError
            wanted[iid] = wanted.get(iid, 0) + qty
    except (ValueError, KeyError, TypeError):
        flash("Invalid order data. Please try again.", "danger")
        return redirect(url_for('cashier'))

    if not customer or len(customer) > 100:
        flash("Enter the student / customer ID or name.", "danger")
        return redirect(url_for('cashier'))
    if not wanted:
        flash("Add at least one item to the order.", "danger")
        return redirect(url_for('cashier'))

    menu_rows = Menu.query.filter(Menu.item_id.in_(wanted.keys()),
                                  Menu.is_deleted == False,
                                  Menu.is_available == True).all()
    if len(menu_rows) != len(wanted):
        flash("One or more items are no longer available. Please check the order.", "danger")
        return redirect(url_for('cashier'))

    # unique token number
    while True:
        token_number = f"TKN-{random.randint(1000, 9999)}"
        if not Digital_token.query.filter_by(token_number=token_number).first():
            break

    total = 0.0
    now = datetime.now()
    for m in menu_rows:
        qty = wanted[m.item_id]
        line_total = m.price * qty
        total += line_total

        new_order = Order(name=customer, total_amount=line_total, pickup_slot=pickup,
                          order_status=True, item_id=m.item_id, is_deleted=False)
        db.session.add(new_order)
        db.session.flush()

        db.session.add(Payment(Payment_amount=line_total, date_time=now,
                               payment_status=pay_mode, item_id=m.item_id, is_deleted=False))
        db.session.add(Digital_token(token_number=token_number, name=m.name, price=m.price,
                                     quantity=qty, is_available=True, item_id=m.item_id,
                                     order_id=new_order.order_id, is_deleted=False))
    db.session.commit()

    flash(f"Token {token_number} issued for {customer} - Rs. {total:,.0f} ({pay_mode}).", "success")
    return redirect(url_for('cashier') + '#token')


@app.route('/cashier/token/<token_number>/serve', methods=['POST'])
@role_required('cashier')
def cashier_serve_token(token_number):
    lines = Digital_token.query.filter_by(token_number=token_number, is_deleted=False).all()
    if not lines:
        flash("Token not found.", "danger")
        return redirect(url_for('cashier') + '#verify')
    for t in lines:
        t.is_available = False
        t.kitchen_status = 'Completed'
    db.session.commit()
    flash(f"Token {token_number} marked as served.", "success")
    return redirect(url_for('cashier', verify=token_number) + '#verify')


# ======================= KITCHEN STAFF =======================
STATUS_ORDER = ['Pending', 'Preparing', 'Ready', 'Completed']
KITCHEN_FLOW = {                      # current status -> (next status, button label)
    'Pending':   ('Preparing', 'Start Preparing'),
    'Preparing': ('Ready', 'Mark Ready'),
    'Ready':     ('Completed', 'Handed Over'),
}


def time_ago(dt):
    if not dt:
        return '-'
    mins = int((datetime.now() - dt).total_seconds() // 60)
    if mins < 1:
        return 'Just now'
    if mins < 60:
        return f"{mins} min{'s' if mins != 1 else ''} ago"
    return f"{mins // 60} hr {mins % 60} min ago"


def kitchen_groups(statuses, newest_first=False, row_limit=None):
    q = db.session.query(Digital_token, Order.name, Order.pickup_slot) \
        .join(Order, Digital_token.order_id == Order.order_id) \
        .filter(Digital_token.is_deleted == False,
                Digital_token.kitchen_status.in_(statuses))
    q = q.order_by(Digital_token.token_id.desc() if newest_first else Digital_token.token_id)
    if row_limit:
        q = q.limit(row_limit)

    groups = {}
    for t, customer, pickup in q.all():
        g = groups.setdefault(t.token_number, {
            'number': t.token_number, 'customer': customer, 'pickup': pickup,
            'lines': [], 'status': t.kitchen_status, 'id': t.token_id, 'created': t.created_at})
        g['lines'].append(t)
        g['id'] = max(g['id'], t.token_id)
        if STATUS_ORDER.index(t.kitchen_status) < STATUS_ORDER.index(g['status']):
            g['status'] = t.kitchen_status
        if t.created_at and (not g['created'] or t.created_at < g['created']):
            g['created'] = t.created_at

    result = sorted(groups.values(), key=lambda g: g['id'], reverse=newest_first)
    for g in result:
        g['age'] = time_ago(g['created'])
        g['next'] = KITCHEN_FLOW.get(g['status'])
    return result


@app.route('/staff', endpoint='staff')
@role_required('staff')
def staff_page():
    view = 'completed' if request.args.get('view') == 'completed' else 'active'

    if view == 'completed':
        orders = kitchen_groups(['Completed'], newest_first=True, row_limit=200)[:20]
    else:
        orders = kitchen_groups(['Pending', 'Preparing', 'Ready'])

    counts = {k: 0 for k in ('Pending', 'Preparing', 'Ready')}
    if view == 'active':
        for g in orders:
            counts[g['status']] += 1

    return render_template('staff.html', staff_user=current_user(),
                           view=view, orders=orders, counts=counts)


@app.route('/staff/token/<token_number>/status', methods=['POST'])
@role_required('staff')
def staff_update_status(token_number):
    new_status = request.form.get('status')
    lines = Digital_token.query.filter_by(token_number=token_number, is_deleted=False).all()
    if not lines:
        flash("Token not found.", "danger")
        return redirect(url_for('staff'))

    # only allow the next step in the flow (Pending -> Preparing -> Ready -> Completed)
    current = min((t.kitchen_status for t in lines), key=STATUS_ORDER.index)
    allowed = KITCHEN_FLOW.get(current)
    if not allowed or allowed[0] != new_status:
        flash("That order was already updated. Screen refreshed.", "warning")
        return redirect(url_for('staff'))

    for t in lines:
        t.kitchen_status = new_status
        if new_status == 'Completed':
            t.is_available = False
    db.session.commit()
    flash(f"{token_number} is now {new_status}.", "success")
    return redirect(url_for('staff'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html')


# ======================= NORMAL LOGIN / SIGNUP =======================
@app.route('/login', methods=['GET', 'POST'])
def login():
    user = current_user()

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        nxt = safe_next(request.form.get('next'))

        user = User.query.filter(func.lower(User.email) == email,
                                 User.is_deleted == False).first()

        if user and check_password_hash(user.password, password):
            session.clear()
            session['user_id'] = user.user_id
            # go where they were heading (e.g. /staff) if their role allows it,
            # otherwise to their own dashboard
            if nxt and next_allowed(user, nxt):
                return redirect(nxt)
            return redirect(home_for(user))

        flash("Invalid email or password.", "danger")
        return redirect(url_for('login', next=nxt) if nxt else url_for('login'))

    nxt = safe_next(request.args.get('next'))
    if user:                                   # already logged in
        return redirect(nxt if nxt and next_allowed(user, nxt) else home_for(user))
    return render_template('login.html', next=nxt)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        role_id = request.form.get('role')
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Only Cashier / Staff can sign up - never Admin
        chosen_role = db.session.get(Role, role_id) if role_id else None
        if (not chosen_role or chosen_role.is_deleted
                or role_group_of_name(chosen_role.name) not in ('cashier', 'staff')):
            flash("Please choose a valid role.", "danger")
            return redirect(url_for('signup'))

        if not full_name or not email:
            flash("Name and email are required.", "danger")
            return redirect(url_for('signup'))

        if len(email) > 30:
            flash("Email is too long (maximum 30 characters).", "danger")
            return redirect(url_for('signup'))

        if User.query.filter(func.lower(User.email) == email).first():
            flash("Email already exists. Please choose another.", "danger")
            return redirect(url_for('signup'))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Password and confirm password must be same.", "danger")
            return redirect(url_for('signup'))

        db.session.add(User(
            name=full_name,
            email=email,
            password=generate_password_hash(password),
            role_id=chosen_role.role_id,
        ))
        db.session.commit()
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))

    roles = [r for r in Role.query.filter_by(is_deleted=False).order_by(Role.role_id).all()
             if role_group_of_name(r.name) in ('cashier', 'staff')]
    return render_template('signup.html', roles=roles)


# ======================= STARTUP / SEED DATA =======================
ADMIN_NAME = 'Jharana Kunwar'
ADMIN_EMAIL = 'kunwarjharana4@gmail.com'
ADMIN_PASSWORD = 'admin123@'


def ensure_columns():
    """Add the new kitchen columns to an existing quick_cafe.db (create_all won't)."""
    cols = {c['name'] for c in inspect(db.engine).get_columns('digital_token')}
    with db.engine.begin() as conn:
        if 'kitchen_status' not in cols:
            conn.execute(text("ALTER TABLE digital_token ADD COLUMN kitchen_status "
                              "VARCHAR(20) NOT NULL DEFAULT 'Pending'"))
            conn.execute(text("UPDATE digital_token SET kitchen_status = 'Completed' "
                              "WHERE is_available = 0"))
            print("Added digital_token.kitchen_status")
        if 'created_at' not in cols:
            conn.execute(text("ALTER TABLE digital_token ADD COLUMN created_at DATETIME"))
            print("Added digital_token.created_at")


def seed_defaults():
    db.create_all()
    ensure_columns()

    # --- default roles (fix old 'chasier' spelling, keep same role_id) ---
    old_cashier = Role.query.filter(func.lower(Role.name) == 'chasier').first()
    if old_cashier:
        old_cashier.name = 'Cashier'
        db.session.commit()
    if not Role.query.filter(func.lower(Role.name) == 'cashier').first():
        db.session.add(Role(name='Cashier', remarks='Cafe Cashier'))
    if not Role.query.filter(func.lower(Role.name) == 'staff').first():
        db.session.add(Role(name='Staff', remarks='Cafe Staff Member'))
    db.session.commit()

    # --- default menu ---
    if not Menu.query.first():
        default_menu = [
            Menu(name='Veg-khana', price=360.0, is_available=True, is_deleted=False),
            Menu(name='Biryani', price=360.0, is_available=True, is_deleted=False),
            Menu(name='samosa', price=60.0, is_available=True, is_deleted=False),
            Menu(name='Chawmein', price=160.0, is_available=True, is_deleted=False),
            Menu(name='cappuccino', price=180.0, is_available=True, is_deleted=False),
            Menu(name='frech fries', price=160.0, is_available=True, is_deleted=False),
            Menu(name='veg-khana set', price=360.0, is_available=True, is_deleted=False),
            Menu(name='Green tea', price=120.0, is_available=True, is_deleted=False),
            Menu(name='MOMO', price=180.0, is_available=True, is_deleted=False),
            Menu(name='Burger', price=260.0, is_available=True, is_deleted=False),
            Menu(name='chessy-chicken', price=360.0, is_available=True, is_deleted=False),
            Menu(name='pizza', price=460.0, is_available=True, is_deleted=False),
            Menu(name='thakali Set', price=560.0, is_available=True, is_deleted=False),
            Menu(name='Veg-Rice', price=160.0, is_available=True, is_deleted=False),
            Menu(name='Coca-Cola', price=120.0, is_available=True, is_deleted=False),
            Menu(name='Fanta', price=120.0, is_available=True, is_deleted=False),
            Menu(name='Mountain Dew', price=120.0, is_available=True, is_deleted=False),
            Menu(name='Sprite', price=120.0, is_available=True, is_deleted=False),
            Menu(name='Sabji Roti', price=260.0, is_available=True, is_deleted=False)
        ]
        db.session.add_all(default_menu)
        db.session.commit()
        print("Default menu items added successfully!")

    # --- ADMIN role + ADMIN account (self-healing) ---
    admin_role = Role.query.filter(func.lower(Role.name) == 'admin').first()
    if not admin_role:
        admin_role = Role(name='Admin', remarks='System Administrator')
        db.session.add(admin_role)
        db.session.commit()
    elif admin_role.is_deleted:
        admin_role.is_deleted = False
        db.session.commit()

    admin_user = User.query.filter(func.lower(User.email) == ADMIN_EMAIL).first()
    if not admin_user:
        db.session.add(User(name=ADMIN_NAME, email=ADMIN_EMAIL,
                            password=generate_password_hash(ADMIN_PASSWORD),
                            role_id=admin_role.role_id, is_deleted=False))
        db.session.commit()
        print("Default admin created:", ADMIN_EMAIL)
    else:
        # account already existed (e.g. created earlier via signup) -> repair it
        changed = False
        if admin_user.role_id != admin_role.role_id:
            admin_user.role_id = admin_role.role_id; changed = True
        if admin_user.is_deleted:
            admin_user.is_deleted = False; changed = True
        if not check_password_hash(admin_user.password, ADMIN_PASSWORD):
            admin_user.password = generate_password_hash(ADMIN_PASSWORD); changed = True
        if changed:
            db.session.commit()
            print("Existing admin account repaired:", ADMIN_EMAIL)


# Runs no matter how you start the app (python app.py OR flask run)
with app.app_context():
    seed_defaults()


if __name__ == '__main__':
    app.run(debug=True)