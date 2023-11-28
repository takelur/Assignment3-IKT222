import sqlite3
import os
from time import sleep
from werkzeug.security import generate_password_hash

# Directories for the database and schema files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, '../db/database.db')
SCHEMA = os.path.join(BASE_DIR, '../db/schema.sql')

# Secret key for signing cookies (for demo)
SECRET_KEY = '1234567891234567'

# Connect to sqlite database
connection = sqlite3.connect(DATABASE)

# Execute the schema.sql file
with open(SCHEMA) as f:
    connection.executescript(f.read())

# Get a cursor object
cursor = connection.cursor()

# Create default admin user
cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            ('admin', generate_password_hash('admin'), 1)
            )

# Retrieve the ID of the admin user just inserted
admin_id = cursor.lastrowid

# Insert the post using the admin's ID
cursor.execute("INSERT INTO posts (title, content, user_id, image) VALUES (?, ?, ?, ?)",
            ('The very first post!', 'Yay, we finally created a blog website!! How do you like it so far?', admin_id, "firstpost.png")
            )

# Sleep to display posts in order on webpage (no sleep is not enough time inbetween)
sleep(1)

# Insert the post using the admin's ID
cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
            ('Does it also work without an image?', 'This is just a test post to see if I could create a post without uploading an image!', admin_id)
            )

# Create default guest user
cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
            ('guest', generate_password_hash('guestaccount'))
            )


# Insert default comments
cursor.execute("INSERT INTO comments (content, user_id, post_id) VALUES (?, ?, ?)",
            ("Let's go!", admin_id, 1))

cursor.execute("INSERT INTO comments (content, user_id, post_id) VALUES (?, ?, ?)",
            ("can't wait for this! x)", 2, 1))

cursor.execute("INSERT INTO comments (content, user_id, post_id) VALUES (?, ?, ?)",
            ("This is bad... the design sux!", 2, 1))


cursor.execute("INSERT INTO comments (content, user_id, post_id) VALUES (?, ?, ?)",
            ("seems like it worked to me", 2, 2))


# Commit the changes
connection.commit()
# Close the connection
connection.close()