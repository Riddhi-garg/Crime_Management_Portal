import sqlite3
from werkzeug.security import generate_password_hash
import hashlib
import datetime

def hash_aadhaar(aadhaar_str):
    return hashlib.sha256(aadhaar_str.encode('utf-8')).hexdigest()

test_citizens = [
    ('Test Citizen One', 'testcitizen1@example.test', '111111111111', 2),
    ('Test Citizen Two', 'testcitizen2@example.test', '222222222222', 1),
    ('Test Citizen Three', 'testcitizen3@example.test', '333333333333', 0),
    ('Test Citizen Four', 'testcitizen4@example.test', None, 0)
]

def seed():
    conn = sqlite3.connect('data/crms.db')
    c = conn.cursor()
    today = datetime.date.today().isoformat()

    for name, email, aadhaar, case_count in test_citizens:
        pwd = generate_password_hash('password123')
        ahash = hash_aadhaar(aadhaar) if aadhaar else None
        alast4 = aadhaar[-4:] if aadhaar else None
        
        c.execute('SELECT user_id FROM users WHERE username = ? OR email = ?', (email, email))
        user_row = c.fetchone()
        if not user_row:
            c.execute('INSERT INTO users (username, email, password, full_name, role, email_verified, aadhaar_hash, aadhaar_last4) VALUES (?, ?, ?, ?, ?, 1, ?, ?)',
                      (email, email, pwd, name, 'Citizen', ahash, alast4))
            user_id = c.lastrowid
        else:
            user_id = user_row[0]
            c.execute('UPDATE users SET aadhaar_hash=?, aadhaar_last4=?, email_verified=1 WHERE user_id=?', (ahash, alast4, user_id))

        c.execute('SELECT victim_id FROM victims WHERE name = ?', (name,))
        victim_row = c.fetchone()
        if not victim_row:
            c.execute('INSERT INTO victims (name, age, gender, address, phone) VALUES (?, ?, ?, ?, ?)', 
                      (name, 30, 'Other', 'TEST ADDRESS', '0000000000'))
            victim_id = c.lastrowid
        else:
            victim_id = victim_row[0]

        # Synthetic test FIRs and cases removed per user requirements
        pass

    conn.commit()
    conn.close()
    print('Test citizens seeded successfully.')

if __name__ == '__main__':
    seed()
