def lookup_account(cursor, user_id):
    query = f"SELECT id, username FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
