import sqlite3

def remove():
    conn = sqlite3.connect('data/crms.db')
    c = conn.cursor()
    
    # 1. Get test victim IDs and FIR IDs
    c.execute("SELECT victim_id FROM victims WHERE name LIKE 'Test Citizen %'")
    victim_ids = [row[0] for row in c.fetchall()]
    
    if not victim_ids:
        print("No test records found.")
        return
        
    placeholders = ','.join('?' for _ in victim_ids)
    
    c.execute(f"SELECT fir_id, crime_id FROM FIR WHERE victim_id IN ({placeholders})", victim_ids)
    rows = c.fetchall()
    fir_ids = [r[0] for r in rows]
    crime_ids = [r[1] for r in rows]
    
    # 2. Delete Cases
    if fir_ids:
        f_placeholders = ','.join('?' for _ in fir_ids)
        c.execute(f"DELETE FROM cases WHERE fir_id IN ({f_placeholders})", fir_ids)
        c.execute(f"DELETE FROM FIR WHERE fir_id IN ({f_placeholders})", fir_ids)
        
    # 3. Delete Crimes
    if crime_ids:
        c_placeholders = ','.join('?' for _ in crime_ids)
        c.execute(f"DELETE FROM crimes WHERE crime_id IN ({c_placeholders})", crime_ids)
        
    # 4. Delete Victims
    c.execute(f"DELETE FROM victims WHERE victim_id IN ({placeholders})", victim_ids)
    
    # 5. Delete Users
    c.execute("DELETE FROM users WHERE username LIKE 'testcitizen%@example.test'")
    
    conn.commit()
    conn.close()
    print("Test citizens and related records removed successfully.")

if __name__ == '__main__':
    remove()
