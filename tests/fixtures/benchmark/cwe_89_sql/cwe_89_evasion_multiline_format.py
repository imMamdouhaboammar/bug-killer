import sqlite3

def query_financial_records(db_connection, account_id):
    # Evasion pattern: multiline f-string with aliasing attempting to bypass naive regex
    cursor = db_connection.cursor()
    target_filter = f"acc_{account_id}"
    sql_text = (
        f"SELECT account_id, balance, status "
        f"FROM account_ledger "
        f"WHERE account_id = '{target_filter}' "
        f"ORDER BY updated_at DESC"
    )
    cursor.execute(sql_text)
    return cursor.fetchall()
