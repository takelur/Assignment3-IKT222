import os
import bleach
import pyotp
import io
import qrcode
import base64
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from db_controller import DatabaseController

# Directories for the database and base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, '../db/database.db')

# Database instance
db = DatabaseController(DATABASE)

APP_SECRET_KEY = '1234567891234567'
SSL_CERT = os.path.join(BASE_DIR, 'server.crt')
SSL_KEY = os.path.join(BASE_DIR, 'server.key')

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

# Initialize the Limiter
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Initialize the OAuth object to Google OAuth2 provider
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id='436966627401-cvo2ojng8ule3lehtqf5ipta2jafm66g.apps.googleusercontent.com',
    client_secret='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',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    authorize_params=None,
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/callback',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

# Allowed file extensions for image upload
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


# Function to generate TOTP QR code
def generate_qr_code(totp_uri):
    # Generate QR code
    image = qrcode.make(totp_uri)

    # Save QR code to byte stream to view in template
    byte_stream = io.BytesIO()
    image.save(byte_stream, 'PNG')
    byte_stream.seek(0)

    return byte_stream

# Route for the root page
@app.route('/')
def index():
    posts = db.get_all_posts()

    if posts is None:
        print("Error retrieving posts from database") # log to console
        return render_template('500.html'), 500
    else:
        return render_template('index.html', posts=posts)


# Route to create a new post
@app.route('/create', methods=('GET', 'POST'))
def create():
    # Check if submit is pressed
    if request.method == 'POST':
        # Set post data
        title = bleach.clean(request.form['title'])
        content = bleach.clean(request.form['content'])

        user_id = db.get_current_user_id(session) # defaults to guest if not logged in
               
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
                    flash("Error saving image file. Please try again.", "error")
                    return render_template('create.html')

                # Insert post with image
                success = db.execute('INSERT INTO posts (title, content, image, user_id) VALUES (?, ?, ?, ?)',
                                     (title, content, new_filename, user_id))
                if not success:
                    return render_template('500.html'), 500
        else:
           # Insert post without image
            success = db.execute('INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
                                 (title, content, user_id))
            if not success:
                return render_template('500.html'), 500

        # Return after successful post creation
        return redirect(url_for('index'))

    else:
        # Return the create.html template if no post request is made
        return render_template('create.html')


# Route to delete a post
@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    post = db.get_post(post_id)

    if not post:
        return render_template('404.html'), 404

    # Check if the current user is the owner or an admin
    if session.get('username') == post['username'] or session.get('is_admin'):

        # First, delete all comments associated with the post
        if not db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,)):
            return render_template('500.html'), 500
        
        # then delete the image file, if it exists
        if post['image']:
            try:
                os.remove(os.path.join(app.root_path, 'static/images', post['image']))
            except OSError as e:
                print(f"Error deleting image file {post['image']}: {e}")
                flash("Error deleting image file. Please try again.", "error")
                return redirect(url_for('post', post_id=post_id))
        # finally, delete the post itself
        if not db.execute('DELETE FROM posts WHERE id = ?', (post_id,)):
            return render_template('500.html'), 500
        
        # Return to home page
        return redirect(url_for('index'))
    else:
        # Return error message
        flash("You do not have permission to delete this post.", "error")
        print(f"User {session.get('username')} attempted to delete post {post_id}")
        return redirect(url_for('post', post_id=post_id))


# Route to search for posts
@app.route('/search', methods=['GET'])
def search():
    # Retrieve search term
    search_term = bleach.clean(request.args.get('search_term', ''))

    posts = db.search_posts(search_term)

    if posts is None:
        return render_template('500.html'), 500

    # If no posts are found, return the index.html template with an empty posts list
    if not posts:
        return render_template('index.html', posts=[], search_term=search_term)
    else:
        # Else return the index.html template with the posts list
        return render_template('index.html', posts=posts, search_term=search_term)


# Route to view a single post
@app.route('/post/<int:post_id>', methods=['GET'])
def post(post_id):
    post = db.get_post(post_id)

    if not post:
        return render_template('404.html'), 404
    
    comments = db.get_comments(post_id)
   
    # Go to post template with the post and comments
    return render_template('post.html', post=post, comments=comments)


# Route to add a comment
@app.route('/add_comment/<int:post_id>', methods=['GET', 'POST'])
def add_comment(post_id):
    if request.method == 'POST':
        # Retrieve content
        comment_content = bleach.clean(request.form['comment_content'])
        user_id = db.get_current_user_id(session)  # defaults to guest if not logged in

        # Insert the comment into the DB using DatabaseController
        success = db.execute('INSERT INTO comments (content, post_id, user_id) VALUES (?, ?, ?)',
                             (comment_content, post_id, user_id))

        if not success:
            return render_template('500.html'), 500

    # Refreshes the post page
    return redirect(url_for('post', post_id=post_id))



# Route to delete a comment
@app.route('/delete_comment/<int:comment_id>', methods=['GET', 'POST'])
def delete_comment(comment_id):
    # Retrieve comment using DatabaseController method
    comment = db.get_comment(comment_id)

    if not comment:
        return render_template('404.html'), 404

    # Check if the current user is the owner of the comment or an admin
    if session.get('username') == comment['username'] or session.get('is_admin'):
        # Delete the comment using DatabaseController
        success = db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
        if not success:
            return render_template('500.html'), 500
    else:
        flash("You do not have permission to delete this comment.", "error")

    # Refresh post page
    return redirect(url_for('post', post_id=comment['post_id']))



# Route to login
@app.route('/login', methods=['GET'])
def show_login():
    show_totp_field = session.get('show_totp_field', False)
    return render_template('login.html', show_totp_field=show_totp_field)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per 10 minutes")
def login():
    # If temp username is in session, the user is at the TOTP verification steop
    if 'temp_username' in session:
        totp_code = request.form.get('totp_code')

        # Retrieve user using DatabaseController
        user = db.get_user_by_username(session['temp_username'])

        if user is None:
            session.pop('temp_username', None)
            session.pop('show_totp_field', None)
            return render_template('500.html'), 500
        
        # Check if TOTP code is valid
        if user and user['totp_secret'] and pyotp.TOTP(user['totp_secret']).verify(totp_code):
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            session.pop('temp_username', None)  # Clean up
            session.pop('show_totp_field', None)
            return redirect(url_for('index'))
        else:
            flash("Invalid TOTP code. Please try again.", "error")
            session.pop('temp_username', None)  # Clean up
            session.pop('show_totp_field', None)

    # Initial login step
    else:
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Please enter both username and password.", "error")
        else:
            # Retrieve user using DatabaseController
            user = db.get_user_by_username(username)

            if user is None:
                return render_template('500.html'), 500

            # Return if password is None (OAuth users)
            if not user["password"]:
                flash("You cannot log in locally with an OAuth2 account, please use Google", "error")
                return redirect(url_for('login'))

            # Verify password and go to TOTP if the user has a secret
            if user and check_password_hash(user['password'], password) and user['totp_secret']:
                # Set temp username for TOTP verification
                session['temp_username'] = user['username']
                session['show_totp_field'] = True
                return redirect(url_for('show_login'))
            # Log in if no TOTP is used
            elif user and check_password_hash(user['password'], password) and not user['totp_secret']:
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                return redirect(url_for('index'))
            else:
                flash("Incorrect username or password. Please try again.", "error")
    
    return redirect(url_for('show_login'))

# Route to login with Google OAuth2
@app.route('/login_google')
def login_google():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

# Route callback for Google OAuth2
@app.route('/callback')
def authorize_google():
    # Error handling if blank callback
    if not request.args.get('code'):
        flash("Google login failed. Please try again.", "error")
        return redirect(url_for('login'))

    # Get client and retrieve token
    google = oauth.create_client('google')
    try:
        token = google.authorize_access_token()
    except:
        flash("Google login failed. Please try again.", "error")
        return redirect(url_for('login'))

    if not token:
        flash("Google login failed. Please try again.", "error")
        return redirect(url_for('login'))
    
    # Fetch user info
    resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
    user_info = resp.json()

    username = user_info['email']

    # Check if user exists
    user = db.get_user_by_username(username)

    if user is None:
        # Create a new user if not exists
        error = db.create_user(username)
        if error:
            flash(error, "error")
            return render_template('500.html'), 500
        session['username'] = username
        session['is_admin'] = False
    else:
        # Log in if user exists
        session['username'] = user['username']
        session['is_admin'] = user['is_admin']

    return redirect(url_for('index'))


# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))


# Route to register account
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_pw = request.form['confirm_password']

        # Sanitize input
        if bleach.clean(username) != username:
            flash("Username contains invalid characters. Please try again.", "error")
        # Check if passwords match
        elif password != confirm_pw:
            flash("Passwords do not match. Please try again.", "error")
        else:
            user = db.get_user_by_username(username)

            if user:
                flash("Username already exists. Please choose a different username.", "error")
            else:
                # Generate password hash
                password_hash = generate_password_hash(password)

                # Generate totp secret
                totp_secret = pyotp.random_base32()

                # Provision uri for QR code
                totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(username, issuer_name="YourAppName")

                # Generate QR code
                qr_byte_stream = generate_qr_code(totp_uri)

                # Convert QR code to a data URL
                qr_data_url = "data:image/png;base64," + base64.b64encode(qr_byte_stream.getvalue()).decode()

                # Store TOTP secret and other temp data in session for verification
                session['temp_totp_secret'] = totp_secret
                session['temp_username'] = username
                session['temp_password_hash'] = password_hash

                # Return the register page with QR code data
                return render_template('register.html', qr_code_data=qr_data_url, show_totp_verification=True)

    return render_template('register.html', qr_code_data="", show_totp_verification=False)


# Route to verify TOTP code
@app.route('/verify_totp', methods=['POST'])
@limiter.limit("5 per 10 minutes")
def verify_totp():
    totp_code = request.form['totp_code']
    # Remove temp data from session
    totp_secret = session.pop('temp_totp_secret', None)
    username = session.pop('temp_username', None)
    password_hash = session.pop('temp_password_hash', None)

    # Check if TOTP code is valid
    if totp_secret and pyotp.TOTP(totp_secret).verify(totp_code):
        error = db.create_user(username, password_hash, totp_secret)

        if error:
            flash("Something went wrong while creating your user, please try again", "error")
            return render_template('500.html'), 500

        return redirect(url_for('login'))
    else:
        flash("Invalid TOTP code. Please register again.", "error")
        return redirect(url_for('register'))
    
# Add CSP headesr to responses
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
    return response

# Redirect to HTTPS
#@app.before_request
#def before_request():
#    if not request.is_secure:
#        url = request.url.replace('http://', 'https://', 1)
#        code = 301
#        return redirect(url, code=code)


if __name__ == "__main__":

    # Commented for security (as explained in report assignment 2)
    #app.config['SESSION_COOKIE_HTTPONLY'] = False

    app.run(debug=True)
    #app.run(debug=True, ssl_context=(SSL_CERT, SSL_KEY))
