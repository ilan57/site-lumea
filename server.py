from flask import Flask, request, jsonify, send_from_directory
import sqlite3, bcrypt, os
from datetime import datetime, timedelta
from functools import wraps

try:
    import jwt
except ImportError:
    import PyJWT as jwt

try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False

app = Flask(__name__, static_folder='.')

SECRET_KEY = os.environ.get('SECRET_KEY', 'lumea-secret-key-2026')
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@lumea.fr')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'lumea2026')

if STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


# ─── DB ──────────────────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lumea.db')

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            prenom TEXT DEFAULT '',
            nom TEXT DEFAULT '',
            telephone TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT NOT NULL,
            prenom TEXT DEFAULT '',
            nom TEXT DEFAULT '',
            telephone TEXT DEFAULT '',
            adresse TEXT DEFAULT '',
            ville TEXT DEFAULT '',
            code_postal TEXT DEFAULT '',
            pays TEXT DEFAULT 'France',
            quantite INTEGER DEFAULT 1,
            total REAL NOT NULL,
            frais_livraison REAL DEFAULT 0,
            statut TEXT DEFAULT 'en_attente',
            stripe_session_id TEXT,
            tracking_number TEXT,
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            prix REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            sku TEXT DEFAULT ''
        );
    ''')
    existing = db.execute('SELECT id FROM products WHERE id=1').fetchone()
    if not existing:
        db.execute(
            "INSERT INTO products (nom, prix, stock, sku) VALUES (?, ?, ?, ?)",
            ('LUMÉA™ Pro Masque LED', 129.0, 47, 'LM-PRO-001')
        )
    db.commit()
    db.close()

init_db()


# ─── JWT ─────────────────────────────────────────────────────────────────────

def create_token(user_id, email, is_admin=False):
    payload = {
        'user_id': user_id,
        'email': email,
        'is_admin': is_admin,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token manquant'}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user = payload
        except Exception:
            return jsonify({'error': 'Token invalide'}), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Non autorisé'}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if not payload.get('is_admin'):
                return jsonify({'error': 'Accès admin requis'}), 403
            request.user = payload
        except Exception:
            return jsonify({'error': 'Token invalide'}), 401
        return f(*args, **kwargs)
    return decorated


# ─── PAGES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/checkout')
@app.route('/checkout/success')
def checkout_page():
    return send_from_directory('.', 'checkout.html')

@app.route('/account')
def account_page():
    return send_from_directory('.', 'account.html')

@app.route('/admin')
def admin_page():
    return send_from_directory('.', 'admin.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)


# ─── AUTH ────────────────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    prenom = data.get('prenom', '')
    nom = data.get('nom', '')

    if not email or not password:
        return jsonify({'error': 'Email et mot de passe requis'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Mot de passe trop court (6 caractères min)'}), 400

    db = get_db()
    if db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
        db.close()
        return jsonify({'error': 'Cet email est déjà utilisé'}), 400

    hash_ = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db.execute(
        'INSERT INTO users (email, password_hash, prenom, nom) VALUES (?,?,?,?)',
        (email, hash_, prenom, nom)
    )
    db.commit()
    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    db.close()

    token = create_token(user['id'], email)
    return jsonify({'token': token, 'user': {'id': user['id'], 'email': email, 'prenom': prenom, 'nom': nom}})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')

    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        token = create_token(0, ADMIN_EMAIL, is_admin=True)
        return jsonify({'token': token, 'user': {'email': ADMIN_EMAIL, 'is_admin': True}})

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    db.close()

    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    token = create_token(user['id'], email)
    return jsonify({'token': token, 'user': {
        'id': user['id'], 'email': user['email'],
        'prenom': user['prenom'], 'nom': user['nom']
    }})

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    db = get_db()
    user = db.execute(
        'SELECT id, email, prenom, nom, telephone, created_at FROM users WHERE id=?',
        (request.user['user_id'],)
    ).fetchone()
    db.close()
    if not user:
        return jsonify({'error': 'Utilisateur introuvable'}), 404
    return jsonify(dict(user))

@app.route('/api/auth/update', methods=['PUT'])
@require_auth
def update_profile():
    data = request.json or {}
    prenom = data.get('prenom')
    nom = data.get('nom')
    telephone = data.get('telephone')
    db = get_db()
    db.execute(
        'UPDATE users SET prenom=COALESCE(?,prenom), nom=COALESCE(?,nom), telephone=COALESCE(?,telephone) WHERE id=?',
        (prenom, nom, telephone, request.user['user_id'])
    )
    db.commit()
    db.close()
    return jsonify({'success': True})


# ─── STOCK PUBLIC ─────────────────────────────────────────────────────────────

@app.route('/api/stock', methods=['GET'])
def get_stock():
    db = get_db()
    product = db.execute('SELECT stock, prix FROM products WHERE id=1').fetchone()
    db.close()
    return jsonify({'stock': product['stock'] if product else 0, 'prix': product['prix'] if product else 129.0})


# ─── LIVRAISON ───────────────────────────────────────────────────────────────

EUROPE = ['Belgique', 'Luxembourg', 'Suisse', 'Allemagne', 'Espagne', 'Italie',
          'Pays-Bas', 'Portugal', 'Autriche', 'Danemark', 'Suède', 'Finlande',
          'Pologne', 'Grèce', 'République tchèque', 'Irlande']

def calc_shipping(pays):
    if pays == 'France':
        return 0, '2-3 jours ouvrés'
    elif pays in EUROPE:
        return 9.90, '3-5 jours ouvrés'
    else:
        return 19.90, '5-10 jours ouvrés'

@app.route('/api/shipping', methods=['POST'])
def calculate_shipping():
    pays = (request.json or {}).get('pays', 'France')
    frais, delai = calc_shipping(pays)
    return jsonify({'frais': frais, 'delai': delai, 'pays': pays})


# ─── CHECKOUT ────────────────────────────────────────────────────────────────

@app.route('/api/checkout/session', methods=['POST'])
def create_checkout_session():
    data = request.json or {}
    email = data.get('email', '').strip()
    prenom = data.get('prenom', '').strip()
    nom = data.get('nom', '').strip()
    telephone = data.get('telephone', '').strip()
    adresse = data.get('adresse', '').strip()
    ville = data.get('ville', '').strip()
    code_postal = data.get('code_postal', '').strip()
    pays = data.get('pays', 'France')
    quantite = max(1, min(10, int(data.get('quantite', 1))))

    if not email or not prenom or not nom or not adresse or not ville or not code_postal:
        return jsonify({'error': 'Tous les champs obligatoires doivent être remplis'}), 400

    db = get_db()
    product = db.execute('SELECT stock, prix FROM products WHERE id=1').fetchone()
    if not product or product['stock'] < quantite:
        db.close()
        return jsonify({'error': 'Stock insuffisant'}), 400

    frais_livraison, _ = calc_shipping(pays)
    total = round(product['prix'] * quantite + frais_livraison, 2)

    # User optionnel
    user_id = None
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
        except Exception:
            pass

    cur = db.execute(
        '''INSERT INTO orders (user_id, email, prenom, nom, telephone, adresse, ville,
           code_postal, pays, quantite, total, frais_livraison)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
        (user_id, email, prenom, nom, telephone, adresse, ville,
         code_postal, pays, quantite, total, frais_livraison)
    )
    order_id = cur.lastrowid
    db.commit()
    db.close()

    # Stripe
    if STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
        try:
            line_items = [{
                'price_data': {
                    'currency': 'eur',
                    'product_data': {
                        'name': 'LUMÉA™ Pro Masque LED',
                        'description': '7 couleurs LED · 150 LEDs · USB-C rechargeable',
                    },
                    'unit_amount': int(product['prix'] * 100),
                },
                'quantity': quantite,
            }]
            if frais_livraison > 0:
                line_items.append({
                    'price_data': {
                        'currency': 'eur',
                        'product_data': {'name': 'Frais de livraison'},
                        'unit_amount': int(frais_livraison * 100),
                    },
                    'quantity': 1,
                })

            base_url = request.host_url.rstrip('/')
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=line_items,
                mode='payment',
                customer_email=email,
                success_url=f'{base_url}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}&order_id={order_id}',
                cancel_url=f'{base_url}/checkout',
                metadata={'order_id': str(order_id)},
            )
            db = get_db()
            db.execute('UPDATE orders SET stripe_session_id=? WHERE id=?', (session.id, order_id))
            db.commit()
            db.close()
            return jsonify({'url': session.url, 'order_id': order_id, 'mode': 'stripe'})
        except Exception as e:
            pass

    # Mode démo (sans Stripe configuré)
    return jsonify({
        'url': f'/checkout/success?order_id={order_id}&demo=1',
        'order_id': order_id,
        'mode': 'demo'
    })

@app.route('/api/checkout/confirm', methods=['POST'])
def confirm_order():
    """Confirmer commande en mode démo"""
    data = request.json or {}
    order_id = data.get('order_id')
    if not order_id:
        return jsonify({'error': 'order_id manquant'}), 400
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
    if not order:
        db.close()
        return jsonify({'error': 'Commande introuvable'}), 404
    db.execute("UPDATE orders SET statut='payee' WHERE id=?", (order_id,))
    db.execute('UPDATE products SET stock = MAX(0, stock - ?) WHERE id=1', (order['quantite'],))
    db.commit()
    order = db.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
    db.close()
    return jsonify(dict(order))

@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    if not STRIPE_AVAILABLE:
        return '', 400
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature', '')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return '', 400
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        order_id = session.get('metadata', {}).get('order_id')
        if order_id:
            db = get_db()
            db.execute("UPDATE orders SET statut='payee' WHERE id=?", (order_id,))
            order = db.execute('SELECT quantite FROM orders WHERE id=?', (order_id,)).fetchone()
            if order:
                db.execute('UPDATE products SET stock = MAX(0, stock - ?) WHERE id=1', (order['quantite'],))
            db.commit()
            db.close()
    return '', 200


# ─── ORDERS CLIENT ───────────────────────────────────────────────────────────

@app.route('/api/orders', methods=['GET'])
@require_auth
def get_orders():
    db = get_db()
    orders = db.execute(
        'SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC',
        (request.user['user_id'],)
    ).fetchall()
    db.close()
    return jsonify([dict(o) for o in orders])


# ─── ADMIN ───────────────────────────────────────────────────────────────────

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.json or {}
    if data.get('email', '').lower() == ADMIN_EMAIL and data.get('password') == ADMIN_PASSWORD:
        token = create_token(0, ADMIN_EMAIL, is_admin=True)
        return jsonify({'token': token})
    return jsonify({'error': 'Identifiants incorrects'}), 401

@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    db = get_db()
    total_orders = db.execute(
        "SELECT COUNT(*) FROM orders WHERE statut != 'en_attente'"
    ).fetchone()[0]
    revenue = db.execute(
        "SELECT COALESCE(SUM(total), 0) FROM orders WHERE statut IN ('payee','expediee','livree')"
    ).fetchone()[0]
    pending = db.execute("SELECT COUNT(*) FROM orders WHERE statut='payee'").fetchone()[0]
    shipped = db.execute("SELECT COUNT(*) FROM orders WHERE statut='expediee'").fetchone()[0]
    delivered = db.execute("SELECT COUNT(*) FROM orders WHERE statut='livree'").fetchone()[0]
    stock = db.execute('SELECT stock, prix FROM products WHERE id=1').fetchone()
    customers = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    # Revenus 30 derniers jours
    rev_30 = db.execute(
        "SELECT COALESCE(SUM(total), 0) FROM orders WHERE statut IN ('payee','expediee','livree') AND created_at >= datetime('now', '-30 days')"
    ).fetchone()[0]
    db.close()
    return jsonify({
        'total_orders': total_orders,
        'revenue': round(revenue, 2),
        'revenue_30d': round(rev_30, 2),
        'pending': pending,
        'shipped': shipped,
        'delivered': delivered,
        'stock': stock['stock'] if stock else 0,
        'prix': stock['prix'] if stock else 129.0,
        'customers': customers
    })

@app.route('/api/admin/orders', methods=['GET'])
@require_admin
def admin_orders():
    statut = request.args.get('statut', '')
    search = request.args.get('q', '')
    db = get_db()
    if search:
        orders = db.execute(
            "SELECT * FROM orders WHERE (email LIKE ? OR nom LIKE ? OR prenom LIKE ? OR id=?) ORDER BY created_at DESC LIMIT 100",
            (f'%{search}%', f'%{search}%', f'%{search}%', search if search.isdigit() else -1)
        ).fetchall()
    elif statut:
        orders = db.execute(
            'SELECT * FROM orders WHERE statut=? ORDER BY created_at DESC LIMIT 200',
            (statut,)
        ).fetchall()
    else:
        orders = db.execute(
            'SELECT * FROM orders ORDER BY created_at DESC LIMIT 200'
        ).fetchall()
    db.close()
    return jsonify([dict(o) for o in orders])

@app.route('/api/admin/orders/<int:order_id>', methods=['GET'])
@require_admin
def get_order(order_id):
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
    db.close()
    if not order:
        return jsonify({'error': 'Commande introuvable'}), 404
    return jsonify(dict(order))

@app.route('/api/admin/orders/<int:order_id>', methods=['PUT'])
@require_admin
def update_order(order_id):
    data = request.json or {}
    db = get_db()
    db.execute(
        'UPDATE orders SET statut=COALESCE(?,statut), tracking_number=COALESCE(?,tracking_number), notes=COALESCE(?,notes) WHERE id=?',
        (data.get('statut'), data.get('tracking_number'), data.get('notes'), order_id)
    )
    db.commit()
    order = db.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
    db.close()
    return jsonify(dict(order))

@app.route('/api/admin/stock', methods=['GET'])
@require_admin
def admin_stock():
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id=1').fetchone()
    db.close()
    return jsonify(dict(product))

@app.route('/api/admin/stock', methods=['PUT'])
@require_admin
def update_stock():
    data = request.json or {}
    db = get_db()
    db.execute(
        'UPDATE products SET stock=COALESCE(?,stock), prix=COALESCE(?,prix) WHERE id=1',
        (data.get('stock'), data.get('prix'))
    )
    db.commit()
    product = db.execute('SELECT * FROM products WHERE id=1').fetchone()
    db.close()
    return jsonify(dict(product))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print('Lumea TM - Serveur demarre sur http://127.0.0.1:' + str(port))
    app.run(debug=False, host='0.0.0.0', port=port, use_reloader=False)
