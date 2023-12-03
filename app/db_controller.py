import sqlite3

class DatabaseController:
    def __init__(self, database):
        self.DATABASE = database

    # Function to get the sqlite3 database connection
    def get_db_connection(self):
        try:
            conn = sqlite3.connect(self.DATABASE)
            conn.row_factory = sqlite3.Row  # enables column access by name
            return conn
        except sqlite3.Error as e:
            print(f"Fatal error: {e}")
            return None

    # Function to get all posts from the database
    def get_all_posts(self):
        conn = self.get_db_connection()
        if conn is None:
            return None
        try:
            posts = conn.execute('''
                SELECT posts.id, posts.title, posts.content, posts.created, users.username 
                FROM posts 
                JOIN users ON posts.user_id = users.id
                ORDER BY posts.created DESC
            ''').fetchall()
            return posts
        except sqlite3.Error as e:
            print(f"Fatal error: {e}")
            return None
        finally:
            conn.close()

    # Function to get a single post from the database
    def get_post(self, post_id):
        conn = self.get_db_connection()
        if conn is None:
            return None
        else:
            try:
                post = conn.execute('''
                    SELECT posts.id, posts.title, posts.content, posts.created, posts.image, users.username 
                    FROM posts 
                    JOIN users ON posts.user_id = users.id
                    WHERE posts.id = ?
                ''', (post_id,)).fetchone()
                return post
            except sqlite3.Error as e:
                print(f"Fatal error: {e}")
                return None
            finally:
                conn.close()

    # Function to get all comments for a single post from the database
    def get_comments(self, post_id):
        conn = self.get_db_connection()
        if conn is None:
            return None
        else:
            try:
                comments = conn.execute('''
                    SELECT comments.id, comments.content, comments.created, users.username 
                    FROM comments
                    JOIN users ON comments.user_id = users.id
                    WHERE comments.post_id = ?
                    ORDER BY comments.created DESC
                ''', (post_id,)).fetchall()
                return comments
            except sqlite3.Error as e:
                print(f"Fatal error: {e}")
                return None
            finally:
                conn.close()

    # Function to get a single comment from the database
    def get_comment(self, comment_id):
        conn = self.get_db_connection()
        if conn is None:
            return None
        else:
            try:
                comment = conn.execute('''
                    SELECT comments.id, comments.content, comments.created, comments.post_id, users.username  
                    FROM comments
                    JOIN users ON comments.user_id = users.id
                    WHERE comments.id = ?
                ''', (comment_id,)).fetchone()
                return comment
            except sqlite3.Error as e:
                print(f"Fatal error: {e}")
                return None
            finally:
                conn.close()

    # Function to get the current user's id
    def get_current_user_id(self, session):
        conn = self.get_db_connection()
        if conn is None:
            return 2

        try:
            username = session.get('username')
            if username:
                user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                if user:
                    return user['id']
        except sqlite3.Error as e:
            print(f"Fatal error: {e}")
        finally:
            conn.close()
        
        return 2  # Default user id for "guest" (not logged in users)

    
    # Execute a query
    def execute(self, query, params):
        conn = self.get_db_connection()
        if conn is None:
            return None
        try:
            conn.execute(query, params)
            conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Fatal error: {e}")
            return None
        finally:
            conn.close()

    # Search posts
    def search_posts(self, search_term):
        conn = self.get_db_connection()
        if conn is None:
            return None
        try:
            posts = conn.execute('''
                SELECT posts.id, posts.title, posts.content, posts.created, users.username 
                FROM posts 
                JOIN users ON posts.user_id = users.id
                WHERE posts.title LIKE ? OR posts.content LIKE ?
                ORDER BY posts.created DESC
            ''', ('%' + search_term + '%', '%' + search_term + '%')).fetchall()
            return posts
        except sqlite3.Error as e:
            print(f"Fatal error: {e}")
            return None
        finally:
            conn.close()

    # Get a user by the username
    def get_user_by_username(self, username):
        conn = self.get_db_connection()
        if conn is None:
            return None
        try:
            user = conn.execute('SELECT username, password, totp_secret, is_admin FROM users WHERE username = ?', (username,)).fetchone()
            return user
        except sqlite3.Error as e:
            print(f"Fatal error: {e}")
            return None
        finally:
            conn.close()


    def create_user(self, username, password_hash=None, totp_secret=None, is_admin=False):
        conn = self.get_db_connection()
        if conn is None:
            return 'Database connection failed'

        try:
            if password_hash and totp_secret:
                conn.execute('INSERT INTO users (username, password, totp_secret, is_admin) VALUES (?, ?, ?, ?)',
                             (username, password_hash, totp_secret, is_admin))
            else:
                conn.execute('INSERT INTO users (username, is_admin) VALUES (?, ?)', (username, is_admin))
            conn.commit()
            return None
        except sqlite3.Error as e:
            return f"Fatal error: {e}"
        finally:
            conn.close()