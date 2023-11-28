import sqlite3
import os
import bleach
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Directories for the database and base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, '../db/database.db')

app = Flask(__name__)
app.secret_key = '1234567891234567'

# Function to get the sqlite3 database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # enables column access by name
    return conn

# Function to get all posts from the database
def get_all_posts():
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT posts.id, posts.title, posts.content, posts.created, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created DESC
    ''').fetchall()
    conn.close()
    return posts

# Function to get a single post from the database
def get_post(post_id):
    conn = get_db_connection()
    post = conn.execute('''
        SELECT posts.id, posts.title, posts.content, posts.created, posts.image, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
        WHERE posts.id = ?
    ''', (post_id,)).fetchone()
    conn.close()
    return post

# Function to get all comments for a single post from the database
def get_comments(post_id):
    conn = get_db_connection()
    comments = conn.execute('''
        SELECT comments.id, comments.content, comments.created, users.username 
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ?
        ORDER BY comments.created DESC
    ''', (post_id,)).fetchall()
    conn.close()
    return comments

# Function to get a single comment from the database
def get_comment(comment_id):
    conn = get_db_connection()
    comment = conn.execute('''
        SELECT comments.id, comments.content, comments.created, comments.post_id, users.username  
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.id = ?
    ''', (comment_id,)).fetchone()
    conn.close()
    return comment

# Allowed file extensions for image upload
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Function to get the current user's id
def get_current_user_id():
    username = session.get('username')
    if username:
        conn = get_db_connection()
        user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user:
            return user['id']
    return 2  # Default user id for "guest" (not logged in users)

# Route for the root page
@app.route('/')
def index():
    posts = get_all_posts()
    return render_template('index.html', posts=posts)


# Route to create a new post
@app.route('/create', methods=('GET', 'POST'))
def create():
    # Check if submit is pressed
    if request.method == 'POST':
        # Set post data
        title = bleach.clean(request.form['title'])
        content = bleach.clean(request.form['content'])

        user_id = get_current_user_id() # defaults to guest if not logged in

        conn = get_db_connection()
        # Insert post into database
        conn.execute('INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
                     (title, content, user_id))
        
        # Chek if image file is included in request
        if 'image' in request.files:
            image = request.files['image']

            # Check if file type is allowed
            if image and allowed_file(image.filename):
                file_name, file_extension = os.path.splitext(image.filename)

                # get timestamp
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

                # construct new filename (to avoid overwriting)
                new_filename = f"{file_name}_{timestamp}{file_extension}"
                new_filename = secure_filename(new_filename)

                # Save the file
                try:
                    image.save(os.path.join(app.root_path, 'static/images', new_filename))
                except OSError:
                    print(f"Error saving image file {new_filename}")

                # Store the new filename in the database
                conn.execute('UPDATE posts SET image = ? WHERE title = ?', (new_filename, title))

        conn.commit()
        conn.close()

        # Return after successful post creation
        return redirect(url_for('index'))

    # Return the create.html template if no post request is made
    return render_template('create.html')


# Route to delete a post
@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    conn = get_db_connection()
    post = get_post(post_id)

    if not post:
        conn.close()
        return "Post not found."

    # Check if the current user is the owner or an admin
    if session.get('username') == post['username'] or session.get('is_admin'):
        # First, delete all comments associated with the post
        conn.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
        # then delete the image file,
        if post['image']:
            try:
                os.remove(os.path.join(app.root_path, 'static/images', post['image']))
            except OSError:
                print(f"Error deleting image file {post['image']}")
        # finally, delete the post itself
        conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        conn.commit()
        conn.close()
        # Return to home page
        return redirect(url_for('index'))
    else:
        conn.close()
        # Return error message
        return "You do not have permission to delete this post."


# Route to search for posts
@app.route('/search', methods=['GET'])
def search():
    # Retrieve search term
    search_term = bleach.clean(request.args.get('search_term', ''))

    conn = get_db_connection()

    # Search in DB for posts matching the search term
    posts = conn.execute('''
        SELECT posts.id, posts.title, posts.content, posts.created, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
        WHERE posts.title LIKE ? OR posts.content LIKE ?
        ORDER BY posts.created DESC
    ''', ('%' + search_term + '%', '%' + search_term + '%')).fetchall()

    conn.close()

    # If no posts are found return the index.html template with an empty posts list
    if not posts:
        return render_template('index.html', posts=[], search_term=search_term)
    else:
        # Else return the index.html template with the posts list
        return render_template('index.html', posts=posts, search_term=search_term)


# Route to view a single post
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post(post_id):
    conn = get_db_connection()

    post = get_post(post_id)
    
    comments = get_comments(post_id)

    conn.close()
    # Go to post template with the post and comments
    return render_template('post.html', post=post, comments=comments)


# Route to add a comment
@app.route('/add_comment/<int:post_id>', methods=['GET', 'POST'])
def add_comment(post_id):
    # Retrieve content
    comment_content = bleach.clean(request.form['comment_content'])
    user_id = get_current_user_id() # defaults to guest if not logged in

    conn = get_db_connection()

    # Insert the comment into DB
    conn.execute('INSERT INTO comments (content, post_id, user_id) VALUES (?, ?, ?)',
                 (comment_content, post_id, user_id))
    
    conn.commit()
    conn.close()

    # Refreshes the post page
    return redirect(url_for('post', post_id=post_id))


# Route to delete a comment
@app.route('/delete_comment/<int:comment_id>', methods=['GET', 'POST'])
def delete_comment(comment_id):
    conn = get_db_connection()

    # Retreive comment
    comment = get_comment(comment_id)

    if not comment:
        conn.close()
        return "Comment not found."

    # Check if the current user is the owner of the comment or an admin
    if session.get('username') == comment['username'] or session.get('is_admin'):
        conn.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
        conn.commit()
    else:
        conn.close()
        return "You do not have permission to delete this comment."

    conn.close()

    # Refresh post page
    return redirect(url_for('post', post_id=comment['post_id']))


# Route to login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None  # Initialize error variable

    # Check if submit is pressed
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # Check if username exists
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        # Check if user exists and password is correct
        if user and check_password_hash(user['password'], password):
            # Sets session cookie
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']

            # Redirects to index after login
            return redirect(url_for('index'))
        else:
            error = "Incorrect username or password. Please try again."

    # Refresh with error message if unsuccessful login
    return render_template('login.html', error=error)


# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove the username from the session
    session.pop('is_admin', None)
    return redirect(url_for('index'))


# Route to register account
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None  # Initialize error variable

    # Check if submit is pressed
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_pw = request.form['confirm_password']

        # Check if username contains invalid characters
        if bleach.clean(username) != username:
            error = "Username contains invalid characters. Please try again."
            return render_template('register.html', error=error)

        conn = get_db_connection()
        # Check if username already exists
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

        if existing_user:
            error = "Username already exists. Please choose a different username."
        elif password != confirm_pw:
            error = "Passwords do not match. Please try again."
        else:
            # Generate password hash
            password_hash = generate_password_hash(password)

            # Store login details in the database
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, password_hash))
            
            conn.commit()
            conn.close()

            # Redirect to login on registration
            return redirect(url_for('login'))

        conn.close()

    # Refresh with error message if unsuccessful registration
    return render_template('register.html', error=error)


if __name__ == "__main__":
    # Demo secret key
    app.secret_key = '1234567891234567'

    # Commented for security (as explainedin report)
    #app.config['SESSION_COOKIE_HTTPONLY'] = False

    app.run(debug=True)
