import sqlite3

def get_user_records(db_connection, username):
    # Vulnerable SQL Injection via direct string concatenation
    cursor = db_connection.cursor()
    query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
