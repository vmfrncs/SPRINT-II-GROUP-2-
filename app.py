from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
from psycopg2 import sql
from passlib.hash import pbkdf2_sha256
import secrets

# from your db_config import
from db_config import DATABASE_URL

app = Flask(__name__)
app.secret_key = "SOME_RANDOM_SECRET_KEY"  # Replace with something secure

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# HELPER FUNCTIONS
def get_user_by_student_id(student_id):
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
    SELECT user_id, student_id, password_hash, campus, role, anonymous_hash
      FROM users
     WHERE student_id = %s;
    """
    cur.execute(query, (student_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

def create_user(student_id, password_hash, campus, role):
    conn = get_db_connection()
    cur = conn.cursor()
    anonymous_hash = secrets.token_hex(3)
    insert_query = """
        INSERT INTO users (student_id, password_hash, campus, role, anonymous_hash)
        VALUES (%s, %s, %s, %s, %s);
    """
    cur.execute(insert_query, (student_id, password_hash, campus, role, anonymous_hash))
    conn.commit()
    cur.close()
    conn.close()

def get_posts(filter_tag=None):
    """
    MODIFIED to also select u.student_id so we can display it in Admin.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    base_query = """
    SELECT p.post_id, p.content, p.created_at, p.post_filter,
           u.user_id, u.role, u.anonymous_hash, u.student_id
      FROM posts p
      JOIN users u ON p.user_id = u.user_id
    """
    if filter_tag:
        base_query += " WHERE p.post_filter = %s"
    base_query += " ORDER BY p.created_at DESC;"

    if filter_tag:
        cur.execute(base_query, (filter_tag,))
    else:
        cur.execute(base_query)

    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def create_post_in_db(user_id, content, post_filter):
    conn = get_db_connection()
    cur = conn.cursor()
    insert_query = """
        INSERT INTO posts (user_id, content, post_filter)
        VALUES (%s, %s, %s);
    """
    cur.execute(insert_query, (user_id, content, post_filter))
    conn.commit()
    cur.close()
    conn.close()

def get_post_likes_dislikes_count(post_id):
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
    SELECT 
        SUM(CASE WHEN like_dislike = TRUE THEN 1 ELSE 0 END) as like_count,
        SUM(CASE WHEN like_dislike = FALSE THEN 1 ELSE 0 END) as dislike_count
    FROM post_likes
    WHERE post_id = %s;
    """
    cur.execute(query, (post_id,))
    row = cur.fetchone()
    like_count = row[0] if row[0] else 0
    dislike_count = row[1] if row[1] else 0
    cur.close()
    conn.close()
    return (like_count, dislike_count)

def user_has_liked(user_id, post_id):
    conn = get_db_connection()
    cur = conn.cursor()
    query = "SELECT like_dislike FROM post_likes WHERE user_id = %s AND post_id = %s;"
    cur.execute(query, (user_id, post_id))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row is None:
        return None
    return row[0]

def get_comments_by_post(post_id):
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
    SELECT c.comment_id, c.content, c.created_at,
           u.user_id, u.role, u.anonymous_hash
      FROM comments c
      JOIN users u ON c.user_id = u.user_id
     WHERE c.post_id = %s
     ORDER BY c.created_at ASC;
    """
    cur.execute(query, (post_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def create_comment(post_id, user_id, content):
    conn = get_db_connection()
    cur = conn.cursor()
    insert_query = """
      INSERT INTO comments (post_id, user_id, content)
      VALUES (%s, %s, %s);
    """
    cur.execute(insert_query, (post_id, user_id, content))
    conn.commit()
    cur.close()
    conn.close()

def get_posts_by_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
    SELECT p.post_id, p.content, p.created_at, p.post_filter,
           u.user_id, u.role, u.anonymous_hash, u.student_id
      FROM posts p
      JOIN users u ON p.user_id = u.user_id
     WHERE p.user_id = %s
     ORDER BY p.created_at DESC;
    """
    cur.execute(query, (user_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def get_top_5_liked_posts():
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
    SELECT p.post_id, p.content,
           COALESCE(SUM(CASE WHEN pl.like_dislike = TRUE THEN 1 ELSE 0 END), 0) AS like_count
      FROM posts p
      LEFT JOIN post_likes pl ON p.post_id = pl.post_id
    GROUP BY p.post_id, p.content
    ORDER BY like_count DESC
    LIMIT 5;
    """
    cur.execute(query)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    top_posts = []
    for r in rows:
        top_posts.append({
            'post_id': r[0],
            'content': r[1],
            'like_count': r[2]
        })
    return top_posts

def get_post_owner(post_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM posts WHERE post_id = %s;", (post_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row:
        return row[0]
    return None

def create_report(post_id, user_id, reason):
    conn = get_db_connection()
    cur = conn.cursor()
    insert_query = """
      INSERT INTO reports (post_id, user_id, reason)
      VALUES (%s, %s, %s);
    """
    cur.execute(insert_query, (post_id, user_id, reason))
    conn.commit()
    cur.close()
    conn.close()

def get_post_by_id(post_id):
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
    SELECT p.post_id, p.content, p.created_at, p.post_filter,
           u.user_id, u.role, u.anonymous_hash, u.student_id
      FROM posts p
      JOIN users u ON p.user_id = u.user_id
     WHERE p.post_id = %s
     LIMIT 1;
    """
    cur.execute(query, (post_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

from flask import request

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        student_id = request.form['student_id'].strip()
        password = request.form['password']
        login_as_admin = request.form.get('login_as_admin')

        user = get_user_by_student_id(student_id)
        if not user:
            flash("Invalid Student ID or Password.", "error")
            return redirect(url_for('login'))

        user_id, db_student_id, db_password_hash, campus, role, anonymous_hash = user
        if not pbkdf2_sha256.verify(password, db_password_hash):
            flash("Invalid Student ID or Password.", "error")
            return redirect(url_for('login'))

        if login_as_admin and role != 'Admin':
            flash("You are not an admin.", "error")
            return redirect(url_for('login'))

        session['user_id'] = user_id
        session['student_id'] = db_student_id
        session['role'] = role
        session['anonymous_hash'] = anonymous_hash

        if login_as_admin and role == 'Admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('saf_dashboard'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        student_id = request.form['student_id'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        campus = request.form['campus']
        role = request.form['role']  # Now includes Admin as an option

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('register'))

        existing_user = get_user_by_student_id(student_id)
        if existing_user:
            flash("Student ID already registered!", "error")
            return redirect(url_for('register'))

        password_hash = pbkdf2_sha256.hash(password)
        create_user(student_id, password_hash, campus, role)

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/SAF/dashboard')
def saf_dashboard():
    if 'role' not in session or session['role'] == 'Admin':
        return redirect(url_for('login'))

    filter_tag = request.args.get('filter', None)
    rows = get_posts(filter_tag)
    current_user_id = session['user_id']

    posts_data = []
    for r in rows:
        (post_id, content, created_at, post_filter,
         owner_user_id, owner_role, owner_hash, student_id) = r

        if owner_user_id == current_user_id:
            author_name = f"You ({owner_role})"
            owned_by_current_user = True
        else:
            author_name = f"Anonymous {owner_hash} ({owner_role})"
            owned_by_current_user = False

        like_count, dislike_count = get_post_likes_dislikes_count(post_id)
        comment_rows = get_comments_by_post(post_id)

        comment_list = []
        for c in comment_rows:
            (comment_id, c_content, c_created_at,
             c_user_id, c_role, c_anon_hash) = c
            if c_user_id == current_user_id:
                c_author = f"You ({c_role})"
            else:
                c_author = f"Anonymous {c_anon_hash} ({c_role})"

            comment_list.append({
                'comment_id': comment_id,
                'content': c_content,
                'created_at': c_created_at,
                'author': c_author
            })

        posts_data.append({
            'post_id': post_id,
            'content': content,
            'created_at': created_at,
            'post_filter': post_filter,
            'author': author_name,
            'like_count': like_count,
            'dislike_count': dislike_count,
            'comments': comment_list,
            'owned_by_current_user': owned_by_current_user
        })

    trending_5 = get_top_5_liked_posts()

    return render_template('saf/saf_dashboard.html',
                           posts=posts_data,
                           trending_5=trending_5)

@app.route('/SAF/create_post', methods=['GET', 'POST'])
def create_post():
    if 'role' not in session or session['role'] == 'Admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        content = request.form['content']
        post_filter = request.form.get('post_filter', '')

        create_post_in_db(user_id, content, post_filter)
        flash("Your feedback has been posted.", "success")
        return redirect(url_for('saf_dashboard'))

    return render_template('saf/create_post.html')

@app.route('/SAF/like/<int:post_id>/<action>', methods=['POST'])
def like_post(post_id, action):
    if 'role' not in session or session['role'] == 'Admin':
        return redirect(url_for('login'))

    user_id = session['user_id']
    like_dislike_val = (action == 'like')
    existing = user_has_liked(user_id, post_id)

    conn = get_db_connection()
    cur = conn.cursor()
    if existing is None:
        insert_query = """
          INSERT INTO post_likes (post_id, user_id, like_dislike)
          VALUES (%s, %s, %s);
        """
        cur.execute(insert_query, (post_id, user_id, like_dislike_val))
    else:
        update_query = """
          UPDATE post_likes
             SET like_dislike = %s
           WHERE post_id = %s
             AND user_id = %s;
        """
        cur.execute(update_query, (like_dislike_val, post_id, user_id))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('saf_dashboard'))

@app.route('/SAF/comment/<int:post_id>', methods=['POST'])
def comment_post(post_id):
    if 'role' not in session or session['role'] == 'Admin':
        return redirect(url_for('login'))

    user_id = session['user_id']
    comment_content = request.form['comment_content'].strip()
    if comment_content:
        create_comment(post_id, user_id, comment_content)
    return redirect(url_for('saf_dashboard'))

# FIRST placeholder route RENAME to avoid collision:
@app.route('/SAF/trending_placeholder/<int:post_id>')
def placeholder_view_trending_post(post_id):
    """
    A placeholder route kept in code so we do not remove anything.
    We'll rename it so it doesn't collide with the actual route.
    """
    from flask import redirect, url_for, flash
    # Minimal placeholder logic
    return render_template('saf/trending_post.html',
                           post_id=post_id,
                           content="(some placeholder content)",
                           like_count=99,
                           dislike_count=0,
                           comments=[])

# The actual route for viewing a trending post
@app.route('/SAF/trending_real/<int:post_id>', methods=['GET'])
def view_trending_post(post_id):
    """
    Displays a single 'trending' post, including likes/dislikes and comments.
    """
    if 'role' not in session or session['role'] == 'Admin':
        return redirect(url_for('login'))

    row = get_post_by_id(post_id)
    if not row:
        flash("Trending post not found.", "error")
        return redirect(url_for('saf_dashboard'))

    (db_post_id, db_content, db_created_at, db_filter,
     db_user_id, db_role, db_hash, db_student_id) = row

    like_count, dislike_count = get_post_likes_dislikes_count(post_id)
    comment_rows = get_comments_by_post(post_id)
    comments_list = []
    current_user_id = session['user_id']

    for (comment_id, c_content, c_created_at, c_user_id, c_role, c_anon_hash) in comment_rows:
        if c_user_id == current_user_id:
            c_author = f"You ({c_role})"
        else:
            c_author = f"Anonymous {c_anon_hash} ({c_role})"

        comments_list.append({
            'comment_id': comment_id,
            'content': c_content,
            'created_at': c_created_at,
            'author': c_author
        })

    return render_template('saf/trending_post.html',
                           post_id=post_id,
                           content=db_content,
                           like_count=like_count,
                           dislike_count=dislike_count,
                           comments=comments_list)

@app.route('/SAF/report/<int:post_id>', methods=['GET', 'POST'])
def report_post(post_id):
    if 'role' not in session or session['role'] == 'Admin':
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    owner_id = get_post_owner(post_id)
    if not owner_id:
        flash("Post not found.", "error")
        return redirect(url_for('saf_dashboard'))

    if owner_id == current_user_id:
        flash("You cannot report your own post!", "error")
        return redirect(url_for('saf_dashboard'))

    if request.method == 'POST':
        reason = request.form.get('reason', '').strip()
        if not reason:
            flash("You must provide a reason for reporting.", "error")
            return redirect(url_for('report_post', post_id=post_id))

        create_report(post_id, current_user_id, reason)
        flash("Report submitted successfully.", "success")
        return redirect(url_for('saf_dashboard'))

    return render_template('saf/report_post.html', post_id=post_id)

@app.route('/SAF/submitted_feedback')
def submitted_feedback():
    if 'role' not in session or session['role'] == 'Admin':
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    user_rows = get_posts_by_user(current_user_id)
    posts_data = []

    for r in user_rows:
        (post_id, content, created_at, post_filter,
         owner_user_id, owner_role, owner_hash, student_id) = r

        author_name = f"You ({owner_role})"
        like_count, dislike_count = get_post_likes_dislikes_count(post_id)
        comment_rows = get_comments_by_post(post_id)

        comment_list = []
        for c in comment_rows:
            (comment_id, c_content, c_created_at,
             c_user_id, c_role, c_anon_hash) = c
            if c_user_id == current_user_id:
                c_author = f"You ({c_role})"
            else:
                c_author = f"Anonymous {c_anon_hash} ({c_role})"

            comment_list.append({
                'comment_id': comment_id,
                'content': c_content,
                'created_at': c_created_at,
                'author': c_author
            })

        posts_data.append({
            'post_id': post_id,
            'content': content,
            'created_at': created_at,
            'post_filter': post_filter,
            'author': author_name,
            'like_count': like_count,
            'dislike_count': dislike_count,
            'comments': comment_list
        })

    return render_template('saf/submitted_feedback.html', posts=posts_data)

@app.route('/SAF/manage_account', methods=['GET', 'POST'])
def manage_account():
    if 'role' not in session or session['role'] == 'Admin':
        return redirect(url_for('login'))

    user_id = session['user_id']
    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        campus = request.form.get('campus', '')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE user_id = %s;", (user_id,))
        row = cur.fetchone()
        if not row:
            flash("Error: user not found.", "error")
            cur.close()
            conn.close()
            return redirect(url_for('manage_account'))

        db_password_hash = row[0]
        if old_password and pbkdf2_sha256.verify(old_password, db_password_hash):
            if new_password == confirm_password and new_password:
                new_hash = pbkdf2_sha256.hash(new_password)
                update_query = """
                  UPDATE users
                     SET password_hash = %s,
                         campus = %s
                   WHERE user_id = %s
                """
                cur.execute(update_query, (new_hash, campus, user_id))
                conn.commit()
                flash("Account updated successfully!", "success")
            else:
                flash("New passwords do not match, or no new password provided.", "error")
        else:
            flash("Old password is incorrect.", "error")

        cur.close()
        conn.close()
        return redirect(url_for('manage_account'))

    return render_template('saf/manage_account.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'Admin':
        return redirect(url_for('login'))

    # 1) Fetch all posts with comments, etc.
    posts_db = get_posts()  
    posts_data = []
    for row in posts_db:
        (post_id, content, created_at, post_filter,
         owner_user_id, owner_role, owner_hash, student_id) = row

        like_count, dislike_count = get_post_likes_dislikes_count(post_id)

        comment_rows = get_comments_by_post(post_id)
        comment_list = []
        for c in comment_rows:
            (c_id, c_content, c_created_at,
             c_user_id, c_user_role, c_anon_hash) = c
            c_author = f"{c_user_role} (uid {c_user_id})"
            comment_list.append({
                'comment_id': c_id,
                'content': c_content,
                'created_at': c_created_at,
                'author': c_author
            })

        posts_data.append({
            'post_id': post_id,
            'content': content,
            'created_at': created_at,
            'post_filter': post_filter,
            'role': owner_role,
            'student_id': student_id,
            'like_count': like_count,
            'dislike_count': dislike_count,
            'comments': comment_list
        })

    return render_template('admin/admin_dashboard.html', posts=posts_data)

@app.route('/admin/manage_feedback')
def admin_manage_feedback():
    if 'role' not in session or session['role'] != 'Admin':
        return redirect(url_for('login'))

    # basically the same approach as admin_dashboard,
    # we show “Manage” features (delete, admin comment)
    posts_db = get_posts()
    # Define posts_data exactly like in admin_dashboard
    posts_data = []
    for row in posts_db:
        (post_id, content, created_at, post_filter,
         owner_user_id, owner_role, owner_hash, student_id) = row

        like_count, dislike_count = get_post_likes_dislikes_count(post_id)

        # gather comments
        comment_rows = get_comments_by_post(post_id)
        comment_list = []
        for c in comment_rows:
            (c_id, c_content, c_created_at,
             c_user_id, c_user_role, c_anon_hash) = c
            c_author = f"{c_user_role} (uid {c_user_id})"
            comment_list.append({
                'comment_id': c_id,
                'content': c_content,
                'created_at': c_created_at,
                'author': c_author
            })

        posts_data.append({
            'post_id': post_id,
            'content': content,
            'created_at': created_at,
            'post_filter': post_filter,
            'role': owner_role,
            'student_id': student_id,
            'like_count': like_count,
            'dislike_count': dislike_count,
            'comments': comment_list
        })

    return render_template('admin/admin_manage_feedback.html', posts=posts_data)

# A route to handle admin’s “Delete Post”
@app.route('/admin/delete_post/<int:post_id>', methods=['POST'])
def admin_delete_post(post_id):
    if 'role' not in session or session['role'] != 'Admin':
        return redirect(url_for('login'))

    # do the delete
    conn = get_db_connection()
    cur = conn.cursor()
    delete_query = "DELETE FROM posts WHERE post_id = %s;"
    cur.execute(delete_query, (post_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash("Post deleted successfully.", "success")
    return redirect(url_for('admin_manage_feedback'))

# A route to handle admin’s “Add comment”
@app.route('/admin/comment/<int:post_id>', methods=['POST'])
def admin_comment(post_id):
    if 'role' not in session or session['role'] != 'Admin':
        return redirect(url_for('login'))

    admin_user_id = session['user_id']
    comment_content = request.form.get('comment_content', '').strip()
    if comment_content:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO comments (post_id, user_id, content)
            VALUES (%s, %s, %s);
        """, (post_id, admin_user_id, comment_content))
        conn.commit()
        cur.close()
        conn.close()

        flash("Admin comment added!", "success")
    else:
        flash("No comment text provided.", "error")

    return redirect(url_for('admin_manage_feedback'))

def get_all_reports():
    """
    Return a list of dictionaries for all reported posts.
    Each dict might have:
      {
        'report_id': ...,
        'post_id': ...,
        'reporter_hash': ...,
        'reporter_role': ...,
        'reason': ...,
        'post_content': ...,
        'report_time': ...
      }
    We join the 'reports' table with 'users' (reporter) & 'posts'.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
    SELECT r.report_id,
           r.post_id,
           r.reason,
           r.created_at AS report_time,
           u.anonymous_hash AS reporter_hash,
           u.role AS reporter_role,
           p.content AS post_content
      FROM reports r
      JOIN users u ON r.user_id = u.user_id  -- the reporter
      JOIN posts p ON r.post_id = p.post_id
    ORDER BY r.created_at DESC;
    """
    cur.execute(query)
    rows = cur.fetchall()
    cur.close()
    conn.close()

    # Convert each row into a dict
    # row => (report_id, post_id, reason, report_time, reporter_hash, reporter_role, post_content)
    results = []
    for row in rows:
        results.append({
            'report_id': row[0],
            'post_id': row[1],
            'reason': row[2],
            'report_time': row[3],
            'reporter_hash': row[4],
            'reporter_role': row[5],
            'post_content': row[6],
        })
    return results

@app.route('/admin/view_reports')
def admin_view_reports():
    """
    Show all reported posts with reason, etc.
    """
    if 'role' not in session or session['role'] != 'Admin':
        return redirect(url_for('login'))

    reports_data = get_all_reports()
    return render_template('admin/admin_view_reports.html', reports=reports_data)

@app.route('/admin/view_reported_post/<int:post_id>')
def admin_view_reported_post(post_id):
    if 'role' not in session or session['role'] != 'Admin':
        return redirect(url_for('login'))

    # Suppose get_post_by_id now returns 8 columns:
    # (post_id, title, content, created_at, post_filter, user_id, role, anonymous_hash)
    row = get_post_by_id(post_id)
    if not row:
        flash("Reported post not found.", "error")
        return redirect(url_for('admin_view_reports'))

    # Unpack all 8
    (db_post_id,
     db_title,
     db_content,
     db_created_at,
     db_filter,
     db_user_id,
     db_role,
     db_hash) = row

    # Likes & dislikes
    like_count, dislike_count = get_post_likes_dislikes_count(post_id)

    # Fetch comments
    comment_rows = get_comments_by_post(post_id)
    comments_list = []
    for c in comment_rows:
        (c_id, c_content, c_created_at, c_uid, c_role, c_anon_hash) = c
        c_author = f"Anonymous {c_anon_hash} ({c_role})"
        comments_list.append({
            'comment_id': c_id,
            'content': c_content,
            'created_at': c_created_at,
            'author': c_author
        })

    # If you want to display a "post_author" line:
    post_author = f"Anonymous {db_hash} ({db_role})"

    # Render the template
    return render_template('admin/admin_view_reported_post.html',
                           post_author=post_author,
                           post_filter=db_filter,
                           post_created_at=db_created_at,
                           post_content=db_content,
                           like_count=like_count,
                           dislike_count=dislike_count,
                           comments=comments_list)


if __name__ == '__main__':
    app.run(debug=True)
