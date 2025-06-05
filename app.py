import os
import sqlite3
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    g
)
from functools import wraps
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'Sh48KsO%*#)@sSJfkUEjDUei&21'  

basedir = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(basedir, 'app.db')

# Database helper functions
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    db_conn = g.pop('db', None)
    if db_conn:
        db_conn.close()

def init_db():
    db = get_db()
    cursor = db.cursor()
    # Create the users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    # Create the recipes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recipe (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            difficulty TEXT NOT NULL,
            time_required INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    ''')
    # Create the comments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            rating INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER NOT NULL,
            recipe_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user (id),
            FOREIGN KEY (recipe_id) REFERENCES recipe (id)
        )
    ''')
    db.commit()

# Decorator for routes to require a login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        db = get_db()
        cur = db.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cur.fetchone()
    return dict(current_user=user)

# Home route to display all recipes
@app.route('/')
def index():
    db = get_db()
    # Multiple SELECT statements: here we select recipes and later further filtering may be applied
    cur = db.execute("SELECT * FROM recipe ORDER BY datetime(created_at) DESC")
    recipes = cur.fetchall()
    return render_template('index.html', recipes=recipes)

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if len(username) < 3 or len(password) < 6:
            flash('Username must be at least 3 characters and password at least 6 characters.', 'danger')
            return redirect(url_for('register'))
        db = get_db()
        # SELECT to check for an existing username
        cur = db.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cur.fetchone():
            flash('Username already exists. Choose another.', 'danger')
            return redirect(url_for('register'))
        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO user (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        db.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# User Login 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db()
        cur = db.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cur.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

# Create a new recipe
@app.route('/recipe/new', methods=['GET', 'POST'])
@login_required
def new_recipe():
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        difficulty = request.form['difficulty']
        time_required_str = request.form['time_required'].strip()

        if not title or not description or not difficulty or not time_required_str:
            flash('All fields are required.', 'danger')
            return redirect(url_for('new_recipe'))
        try:
            time_required = int(time_required_str)
            if time_required <= 0:
                raise ValueError
        except ValueError:
            flash('Time required must be a positive number.', 'danger')
            return redirect(url_for('new_recipe'))
        if difficulty not in ['Easy', 'Medium', 'Hard']:
            flash('Invalid difficulty level selected.', 'danger')
            return redirect(url_for('new_recipe'))
        db = get_db()
        db.execute(
            '''INSERT INTO recipe (title, description, difficulty, time_required, user_id)
               VALUES (?, ?, ?, ?, ?)''',
            (title, description, difficulty, time_required, session['user_id'])
        )
        db.commit()
        # Get the last inserted recipe id (multiple SELECTs example)
        recipe_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        flash('Recipe posted successfully.', 'success')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))
    return render_template('new_recipe.html')

def row_to_dict(row):
    return dict(row) if row else None

@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    db = get_db()
    cur = db.execute("SELECT * FROM recipe WHERE id = ?", (recipe_id,))
    recipe_row = cur.fetchone()
    if not recipe_row:
        abort(404)
    recipe = row_to_dict(recipe_row)
    
    cur = db.execute(
        """SELECT c.*, u.username 
           FROM comment c 
           JOIN user u ON c.user_id = u.id 
           WHERE recipe_id = ? 
           ORDER BY datetime(c.created_at) ASC""",
        (recipe_id,)
    )
    comment_rows = cur.fetchall()
    comments = [row_to_dict(comment) for comment in comment_rows] if comment_rows else []
    
    avg_rating = None
    if comments:
        total = sum(comment['rating'] for comment in comments)
        avg_rating = round(total / len(comments), 2)
    return render_template('recipe_detail.html', recipe=recipe, comments=comments, avg_rating=avg_rating)

# Edit a recipe (demonstrates use of the UPDATE statement)
@app.route('/recipe/<int:recipe_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_recipe(recipe_id):
    db = get_db()
    # SELECT to verify existence and ownership of the recipe
    cur = db.execute("SELECT * FROM recipe WHERE id = ?", (recipe_id,))
    recipe = cur.fetchone()
    if not recipe:
        abort(404)
    if recipe['user_id'] != session['user_id']:
        abort(403)
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        difficulty = request.form['difficulty']
        time_required_str = request.form['time_required'].strip()

        if not title or not description or not difficulty or not time_required_str:
            flash('All fields are required.', 'danger')
            return redirect(url_for('edit_recipe', recipe_id=recipe_id))
        try:
            time_required = int(time_required_str)
            if time_required <= 0:
                raise ValueError
        except ValueError:
            flash('Time required must be a positive number.', 'danger')
            return redirect(url_for('edit_recipe', recipe_id=recipe_id))
        if difficulty not in ['Easy', 'Medium', 'Hard']:
            flash('Invalid difficulty level selected.', 'danger')
            return redirect(url_for('edit_recipe', recipe_id=recipe_id))
        # Use the UPDATE statement to modify the recipe
        db.execute(
            '''UPDATE recipe 
               SET title = ?, description = ?, difficulty = ?, time_required = ?
               WHERE id = ?''',
            (title, description, difficulty, time_required, recipe_id)
        )
        db.commit()
        flash('Recipe updated successfully.', 'success')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))
    return render_template('edit_recipe.html', recipe=recipe)

# Delete a recipe (and its comments) using the DELETE statement.
@app.route('/recipe/<int:recipe_id>/delete', methods=['POST'])
@login_required
def delete_recipe(recipe_id):
    db = get_db()
    # SELECT to verify existence and ownership
    cur = db.execute("SELECT user_id FROM recipe WHERE id = ?", (recipe_id,))
    recipe = cur.fetchone()
    if not recipe:
        abort(404)
    if recipe['user_id'] != session['user_id']:
        abort(403)
    # Delete associated comments first
    db.execute("DELETE FROM comment WHERE recipe_id = ?", (recipe_id,))
    # Then delete the recipe itself
    db.execute("DELETE FROM recipe WHERE id = ?", (recipe_id,))
    db.commit()
    flash('Recipe deleted.', 'info')
    return redirect(url_for('index'))

# Add a comment to a recipe
@app.route('/recipe/<int:recipe_id>/comment', methods=['POST'])
@login_required
def add_comment(recipe_id):
    db = get_db()
    # Multiple SELECT statements: Check first if the recipe exists
    cur = db.execute("SELECT * FROM recipe WHERE id = ?", (recipe_id,))
    recipe = cur.fetchone()
    if not recipe:
        abort(404)
    content = request.form['content'].strip()
    try:
        rating = int(request.form.get('rating', 0))
    except ValueError:
        rating = 0
    if not content or rating < 1 or rating > 5:
        flash('Comment and rating (1-5) are required.', 'danger')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))
    db.execute(
        '''INSERT INTO comment (content, rating, user_id, recipe_id)
           VALUES (?, ?, ?, ?)''',
        (content, rating, session['user_id'], recipe_id)
    )
    db.commit()
    flash('Comment added.', 'success')
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Ensure that the database and tables are initialized at startup.
    app.run(debug=True, host='0.0.0.0', port=5000)
