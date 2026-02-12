import sqlite3

def init_db():
    conn = sqlite3.connect('sentinel.db')
    cursor = conn.cursor()
    
    # Tabela de Perfis
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            cpf TEXT,
            phone TEXT,
            rg TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabela de Resultados Encontrados (para evitar alertas duplicados)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER,
            source TEXT,
            content TEXT,
            link TEXT,
            found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(profile_id) REFERENCES profiles(id)
        )
    ''')
    
    conn.commit()
    conn.close()

def add_profile(name, cpf, phone, rg):
    conn = sqlite3.connect('sentinel.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO profiles (name, cpf, phone, rg) VALUES (?, ?, ?, ?)', (name, cpf, phone, rg))
    conn.commit()
    conn.close()

def get_profiles():
    conn = sqlite3.connect('sentinel.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM profiles')
    profiles = cursor.fetchall()
    conn.close()
    return profiles

def remove_profile(profile_id):
    conn = sqlite3.connect('sentinel.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM profiles WHERE id = ?', (profile_id,))
    cursor.execute('DELETE FROM findings WHERE profile_id = ?', (profile_id,))
    conn.commit()
    conn.close()

def add_finding(profile_id, source, content, link):
    conn = sqlite3.connect('sentinel.db')
    cursor = conn.cursor()
    # Verifica se já existe esse achado para esse perfil
    cursor.execute('SELECT id FROM findings WHERE profile_id = ? AND link = ?', (profile_id, link))
    if cursor.fetchone() is None:
        cursor.execute('INSERT INTO findings (profile_id, source, content, link) VALUES (?, ?, ?, ?)', 
                       (profile_id, source, content, link))
        conn.commit()
        conn.close()
        return True
    conn.close()
def get_recent_findings(profile_id):
    conn = sqlite3.connect('sentinel.db')
    cursor = conn.cursor()
    # Pega achados das últimas 24 horas
    cursor.execute('''
        SELECT source, content, link, found_at 
        FROM findings 
        WHERE profile_id = ? AND found_at >= datetime('now', '-1 day')
    ''', (profile_id,))
    findings = cursor.fetchall()
    conn.close()
    return findings

if __name__ == "__main__":
    init_db()
