import sqlite3

def make_db():
    # check_same_thread=False because Flask serves requests on multiple threads
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE customers (id INTEGER, name TEXT, plan TEXT, ssn TEXT)")
    db.executemany("INSERT INTO customers VALUES (?,?,?,?)", [
        (1, "Alice Nguyen", "pro",   "111-22-3333"),
        (2, "Bob Carter",   "free",  "444-55-6666"),
        (3, "Carlos Diaz",  "admin", "777-88-9999"),
    ])
    return db

# Create one shared DB instance other modules can import.
DB = make_db()