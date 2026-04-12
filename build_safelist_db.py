import sqlite3
import csv
import os
import time

def build_db():
    start = time.time()
    csv_path = 'top10milliondomains.csv'
    db_path = 'safe_domains.db'
    
    if os.path.exists(db_path):
        print(f"Database {db_path} already exists. Skipping.")
        return

    print("Building safe_domains.db... this might take a minute.")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('CREATE TABLE domains (domain TEXT PRIMARY KEY)')
    
    batch = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader) # skip header
        for i, row in enumerate(reader):
            if len(row) > 1:
                batch.append((row[1].strip().lower(),))
            if len(batch) >= 100000:
                c.executemany('INSERT OR IGNORE INTO domains (domain) VALUES (?)', batch)
                batch = []
            if i % 1000000 == 0:
                print(f"Processed {i} rows...")
                
    if batch:
        c.executemany('INSERT OR IGNORE INTO domains (domain) VALUES (?)', batch)
        
    conn.commit()
    conn.close()
    print(f"Finished building {db_path} in {time.time() - start:.2f} seconds.")

if __name__ == '__main__':
    build_db()
