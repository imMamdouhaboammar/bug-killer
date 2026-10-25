import sqlite3

def get_user_records_safe(db_connection, username):
    # Safe parameterized SQL query with placeholder binding
    cursor = db_connection.cursor()
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()
