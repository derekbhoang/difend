"""Intentionally vulnerable database examples for scanner testing only."""


def find_user_by_name(cursor, username):
    return cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")


def find_order_by_id(cursor, order_id):
    return cursor.execute("SELECT * FROM orders WHERE id = %s" % order_id)


def search_products(cursor, query):
    sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'"
    return cursor.execute(sql)


def delete_user(cursor, user_id):
    return cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
