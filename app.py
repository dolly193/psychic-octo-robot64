import os
import json
import io
import hashlib
import time
import threading
import mysql.connector
from flask import Flask, request, send_file, jsonify, send_from_directory, session, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import base64
import libtorrent as lt
import google.generativeai as genai

app = Flask(__name__)
app.secret_key = 'brothernoahbrothernoah' # Troque isso em produção

# --- CONFIGURAÇÃO DO GEMINI ---
GEMINI_API_KEY = "AIzaSyD4PBkn5oCq6QIDtSAyiozQVefPIbg9O2A" # <--- COLE SUA CHAVE AQUI
genai.configure(api_key=GEMINI_API_KEY)

# Configurações
UPLOAD_FOLDER = 'storage'
DOLLY_FOLDER = 'dolly_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOLLY_FOLDER, exist_ok=True)

# Chave de criptografia para os arquivos .dolly (Deve ser fixa para poder ler arquivos antigos)
# Em produção, use variáveis de ambiente.
ENCRYPTION_KEY = b'gQjW8_5V4q3z2s1X0o9p8u7y6t5r4e3w2q1a0s9d8f7=' 
cipher_suite = Fernet(ENCRYPTION_KEY)

# --- CONFIGURAÇÃO DO TIDB ---
# Preencha com os dados do seu painel TiDB Cloud
DB_CONFIG = {
    'host': 'gateway01.us-west-2.prod.aws.tidbcloud.com', # Exemplo: troque pelo seu host
    'port': 4000,
    'user': '3jZGJoZm7yRDfbG.root', # Troque pelo seu usuário
    'password': 'zRbX8aXBISsk5Pft', # Troque pela sua senha
    'database': 'test'
}

def get_db_connection():
    """Conecta ao banco de dados TiDB."""
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"Erro de conexão com TiDB: {err}")
        return None

def init_db():
    """Cria a tabela de metadados no TiDB se não existir."""
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS arquivos_dolly (
                hash VARCHAR(64),
                filename VARCHAR(255),
                size_bytes BIGINT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                owner_id INT,
                PRIMARY KEY (hash)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                is_approved BOOLEAN DEFAULT FALSE,
                quota_used BIGINT DEFAULT 0
            )
        """)

        # Migração de Emergência: Adiciona a coluna owner_id se ela estiver faltando
        try:
            cursor.execute("ALTER TABLE arquivos_dolly ADD COLUMN owner_id INT")
        except mysql.connector.Error as err:
            # Ignora o erro 1060 (Duplicate column name) se a coluna já existir
            if err.errno != 1060:
                print(f"Aviso do Banco de Dados: {err}")

        # Migração 2: Adiciona suporte a Magnet Links (para torrents reais no futuro)
        try:
            cursor.execute("ALTER TABLE arquivos_dolly ADD COLUMN magnet_link TEXT")
        except mysql.connector.Error as err:
            # Ignora erro se a coluna já existir
            if err.errno != 1060:
                print(f"Aviso do Banco de Dados (Magnet): {err}")

        # Migração 3: Adiciona coluna para o CONTEÚDO do arquivo (BLOB)
        try:
            # LONGBLOB suporta até 4GB (teoricamente), mas depende do limite de pacote do servidor
            cursor.execute("ALTER TABLE arquivos_dolly ADD COLUMN file_content LONGBLOB")
        except mysql.connector.Error as err:
            if err.errno != 1060:
                print(f"Aviso do Banco de Dados (Blob): {err}")

        # Migração 4: Tabela para pedaços de arquivos (Chunking) para contornar limite de 6MB do TiDB
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_chunks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                file_hash VARCHAR(64),
                chunk_index INT,
                chunk_data LONGBLOB,
                INDEX (file_hash)
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("Banco de dados TiDB conectado e inicializado!")

def calculate_sha256(file_path):
    """Gera um hash único para o arquivo para garantir integridade."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

@app.route('/')
def index():
    return send_file('index.html')

# --- SISTEMA DE LOGIN E ADMIN ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password') # Em produção, use hash (bcrypt/argon2)
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            # Se for o usuário "admin", já cria como admin e aprovado
            is_admin = True if username.lower() == 'admin' else False
            is_approved = True if is_admin else False
            
            cursor.execute("INSERT INTO users (username, password, is_admin, is_approved) VALUES (%s, %s, %s, %s)", 
                           (username, password, is_admin, is_approved))
            conn.commit()
            return jsonify({"message": "Registrado com sucesso! Faça login."})
        except mysql.connector.Error as err:
            return jsonify({"error": "Usuário já existe ou erro no banco."}), 400
        finally:
            conn.close()
    return jsonify({"error": "Erro de conexão"}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session.permanent = True # Mantém o login ativo mesmo ao fechar o navegador
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            session['is_approved'] = user['is_approved']
            session['quota_used'] = user['quota_used']
            return jsonify({"message": "Login realizado", "user": user})
        
    return jsonify({"error": "Credenciais inválidas"}), 401

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({"message": "Logout realizado"})

@app.route('/check_session', methods=['GET'])
def check_session():
    """Verifica se o usuário já está logado."""
    if 'user_id' in session:
        return jsonify({
            "logged_in": True,
            "user": {
                "username": session.get('username'),
                "is_admin": session.get('is_admin'),
                "is_approved": session.get('is_approved')
            }
        })
    return jsonify({"logged_in": False})

@app.route('/admin/pending_users', methods=['GET'])
def list_pending():
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, quota_used FROM users WHERE is_approved = FALSE")
    users = cursor.fetchall()
    conn.close()
    return jsonify(users)

@app.route('/admin/approve/<int:user_id>', methods=['POST'])
def approve_user(user_id):
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_approved = TRUE WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Usuário aprovado!"})

@app.route('/admin/users', methods=['GET'])
def list_all_users():
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, is_approved, quota_used FROM users")
    users = cursor.fetchall()
    conn.close()
    return jsonify(users)

@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Encontrar e deletar todos os arquivos desse usuário para liberar espaço
    cursor.execute("SELECT hash, filename FROM arquivos_dolly WHERE owner_id = %s", (user_id,))
    files = cursor.fetchall()
    
    for f in files:
        # Remove arquivos físicos
        # try:
        #     os.remove(os.path.join(UPLOAD_FOLDER, f['filename']))
        # except OSError:
        #     pass 
        pass
            
    # 2. Remove registros do banco
    cursor.execute("DELETE FROM file_chunks WHERE file_hash IN (SELECT hash FROM arquivos_dolly WHERE owner_id = %s)", (user_id,))
    cursor.execute("DELETE FROM arquivos_dolly WHERE owner_id = %s", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Usuário e seus arquivos deletados!"})

@app.route('/admin/files', methods=['GET'])
def list_all_files():
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT hash, filename, size_bytes, owner_id FROM arquivos_dolly")
    files = cursor.fetchall()
    conn.close()
    return jsonify(files)

@app.route('/my_files', methods=['GET'])
def list_my_files():
    if 'user_id' not in session:
        return jsonify({"error": "Login necessário"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT hash, filename, size_bytes FROM arquivos_dolly WHERE owner_id = %s", (session['user_id'],))
    files = cursor.fetchall()
    conn.close()
    return jsonify(files)

@app.route('/delete_file/<file_hash>', methods=['DELETE'])
def delete_file(file_hash):
    if 'user_id' not in session:
        return jsonify({"error": "Login necessário"}), 401
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Pega info do arquivo para descontar cota e saber nome
    cursor.execute("SELECT filename, size_bytes, owner_id FROM arquivos_dolly WHERE hash = %s", (file_hash,))
    file_data = cursor.fetchone()
    
    if file_data:
        # --- VERIFICAÇÃO DE SEGURANÇA ---
        # Se não for o dono E não for admin, bloqueia a exclusão
        if file_data['owner_id'] != session['user_id'] and not session.get('is_admin'):
            conn.close()
            return jsonify({"error": "Você não pode deletar arquivos de outros usuários!"}), 403

        # Remove físicos
        # try:
        #     os.remove(os.path.join(UPLOAD_FOLDER, file_data['filename']))
        # except OSError:
        #     pass
        pass
            
        # Atualiza cota do dono
        cursor.execute("UPDATE users SET quota_used = quota_used - %s WHERE id = %s", (file_data['size_bytes'], file_data['owner_id']))
        # Deleta registro
        cursor.execute("DELETE FROM arquivos_dolly WHERE hash = %s", (file_hash,))
        conn.commit()
        
    conn.close()
    return jsonify({"message": "Arquivo deletado!"})

def finalize_file_processing(filename, user_id, conn, magnet_link=None):
    """
    Função centralizada para salvar metadados no banco e criar o arquivo .dolly
    """
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    # Garante o tamanho real do arquivo em disco
    file_size = os.path.getsize(file_path)
    file_hash = calculate_sha256(file_path)
    
    cursor = conn.cursor()
    # INSERT IGNORE evita erro se o arquivo já foi cadastrado antes
    # Nota: Passamos None para file_content pois usaremos a tabela de chunks para arquivos novos
    sql = "INSERT IGNORE INTO arquivos_dolly (hash, filename, size_bytes, owner_id, magnet_link, file_content) VALUES (%s, %s, %s, %s, %s, %s)"
    cursor.execute(sql, (file_hash, filename, file_size, user_id, magnet_link, None))
    
    # Se o arquivo foi inserido agora (rowcount > 0), salvamos os chunks
    # Se rowcount == 0, o arquivo já existe, assumimos que os chunks também existem.
    if cursor.rowcount > 0:
        chunk_size = 2 * 1024 * 1024 # 2MB por pedaço (seguro para o limite de 6MB do TiDB)
        with open(file_path, 'rb') as f:
            chunk_index = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                cursor.execute("INSERT INTO file_chunks (file_hash, chunk_index, chunk_data) VALUES (%s, %s, %s)", (file_hash, chunk_index, chunk))
                chunk_index += 1
    
    # Atualiza cota no banco
    cursor.execute("UPDATE users SET quota_used = quota_used + %s WHERE id = %s", (file_size, user_id))
    
    # Cria a estrutura do .dolly
    dolly_data = {
        "protocol": "dolly-v1",
        "original_name": filename,
        "size": file_size,
        "hash": file_hash,
        "download_endpoint": f"/baixar_conteudo/{filename}" 
    }
    if magnet_link:
        dolly_data['magnet_link'] = magnet_link
    
    # Salva o arquivo .dolly criptografado
    dolly_filename = f"{filename}.dolly"
    dolly_path = os.path.join(DOLLY_FOLDER, dolly_filename)
    json_str = json.dumps(dolly_data)
    encrypted_data = cipher_suite.encrypt(json_str.encode())
    
    with open(dolly_path, 'wb') as f:
        f.write(encrypted_data)
        
    # Opcional: Remover o arquivo do disco local já que está no banco (economiza espaço no Render)
    try:
        os.remove(file_path)
    except: pass

    return dolly_path

@app.route('/criar_dolly', methods=['POST'])
def create_dolly():
    """
    1. Recebe o arquivo real.
    2. Salva no servidor.
    3. Cria o arquivo de metadados .dolly.
    4. Retorna o arquivo .dolly para o usuário.
    """
    # Verifica Login e Aprovação
    if 'user_id' not in session:
        return jsonify({"error": "Faça login para criar arquivos"}), 401
    
    if not session.get('is_approved'):
        return jsonify({"error": "Sua conta ainda não foi aprovada pelo Admin"}), 403

    if 'file' not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Nome de arquivo inválido"}), 400

    # Verifica Cota (500MB = 524288000 bytes)
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    if (session.get('quota_used', 0) + file_length) > 524288000:
        return jsonify({"error": "Cota de 500MB excedida!"}), 400
    file.seek(0) # Reseta ponteiro do arquivo

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    # Salva o arquivo original
    file.save(file_path)
    file_size = file_length # Define variável para uso na sessão
    
    # Calcula metadados
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        # Finaliza o processamento (DB, .dolly, cota)
        # A função finalize_file_processing agora retorna o .dolly path
        dolly_path = finalize_file_processing(filename, session['user_id'], conn)

        conn.commit()
        cursor.close()
        conn.close()
        
        # Atualiza sessão local
        session['quota_used'] += file_size
    
    if dolly_path:
        return send_file(dolly_path, as_attachment=True)
    else:
        # Isso pode acontecer se o arquivo já existir e o .dolly não for gerado novamente
        return jsonify({"message": "Arquivo já existe no sistema."}), 200

def download_torrent_and_create_dolly(magnet_link, user_id):
    """
    Função executada em background para baixar um torrent e criar o .dolly.
    """
    # 1. Configurar sessão do libtorrent
    ses = lt.session({'listen_interfaces': '0.0.0.0:6881'})
    params = {'save_path': UPLOAD_FOLDER}
    handle = lt.add_magnet_uri(ses, magnet_link, params)
    ses.start_dht()

    print(f"Iniciando download do torrent para o usuário {user_id}...")

    # 2. Aguardar o download
    while not handle.status().is_seeding:
        s = handle.status()
        print(f'\rBaixando: {s.name} {s.progress * 100:.2f}% completo (vel: {s.download_rate / 1000:.1f} kB/s)', end='')
        time.sleep(1)
    
    print(f"\nDownload de '{handle.status().name}' completo!")
    
    # 3. Pós-processamento
    ti = handle.get_torrent_info()
    
    # Validação: Apenas torrents com UM arquivo são suportados por enquanto
    if ti.num_files() != 1:
        print(f"Erro: O torrent '{ti.name()}' contém {ti.num_files()} arquivos. Apenas torrents com um único arquivo são suportados. Abortando.")
        # Em uma implementação futura, você poderia deletar os arquivos baixados:
        # import shutil
        # shutil.rmtree(os.path.join(UPLOAD_FOLDER, ti.name()))
        return

    filename = secure_filename(ti.name())
    file_size = ti.total_size()

    # 4. Conectar ao DB e finalizar
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            # Verifica cota ANTES de inserir
            cursor.execute("SELECT quota_used FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            
            # Usando a mesma cota de 500MB do upload direto
            if (user['quota_used'] + file_size) > 524288000:
                print(f"Erro de cota para usuário {user_id} ao baixar torrent. Excluindo arquivo.")
                os.remove(os.path.join(UPLOAD_FOLDER, filename))
                return

            # Finaliza o processamento (DB, .dolly, cota)
            finalize_file_processing(filename, user_id, conn, magnet_link=magnet_link)
            conn.commit()
        finally:
            conn.close()
    print(f"Processo de torrent para '{filename}' finalizado.")

@app.route('/add_magnet', methods=['POST'])
def add_magnet():
    """Recebe um link magnético e inicia o download em segundo plano."""
    # 1. Validação de sessão
    if 'user_id' not in session:
        return jsonify({"error": "Faça login para adicionar torrents"}), 401
    
    if not session.get('is_approved'):
        return jsonify({"error": "Sua conta ainda não foi aprovada pelo Admin"}), 403

    # 2. Validação do input
    data = request.json
    magnet_link = data.get('magnet_link')
    if not magnet_link or not magnet_link.startswith('magnet:'):
        return jsonify({"error": "Link magnético inválido"}), 400

    # 3. Iniciar download em background
    thread = threading.Thread(target=download_torrent_and_create_dolly, args=(magnet_link, session['user_id']))
    thread.daemon = True # Permite que o app principal saia mesmo que a thread esteja rodando
    thread.start()

    return jsonify({"message": "Download do torrent iniciado. O arquivo aparecerá em 'Meus Arquivos' quando concluído."})

@app.route('/status')
def status_check():
    """Verifica conectividade com o banco para a tela de intro."""
    conn = get_db_connection()
    if conn:
        conn.close()
        return jsonify({"status": "online", "database": "connected"})
    return jsonify({"error": "Database connection failed"}), 500

@app.route('/ler_dolly', methods=['POST'])
def read_dolly():
    """
    Recebe um arquivo .dolly, lê onde está o arquivo real e inicia o download.
    """
    if 'dolly_file' not in request.files:
        return jsonify({"error": "Envie um arquivo .dolly"}), 400
        
    dolly_file = request.files['dolly_file']
    
    try:
        # Lê e Descriptografa
        encrypted_content = dolly_file.read()
        decrypted_content = cipher_suite.decrypt(encrypted_content)
        metadata = json.loads(decrypted_content.decode())
        
        if metadata.get("protocol") != "dolly-v1":
            return jsonify({"error": "Arquivo .dolly inválido ou versão antiga"}), 400
            
        # Redireciona para a rota de download real
        # Nota: Na prática, o frontend usaria essa URL para baixar
        return jsonify({
            "message": "Arquivo localizado!",
            "file_info": metadata,
            "download_url": metadata['download_endpoint']
        })
        
    except Exception as e:
        return jsonify({"error": f"Erro ao processar .dolly: {str(e)}"}), 500

@app.route('/baixar_conteudo/<filename>')
def download_content(filename):
    """Rota que entrega o arquivo real (binário)."""
    # return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    
    # Agora busca do Banco de Dados
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT hash, file_content FROM arquivos_dolly WHERE filename = %s", (filename,))
        row = cursor.fetchone()
        
        if row:
            # 1. Tenta pegar do método antigo (coluna file_content)
            if row['file_content']:
                conn.close()
                return send_file(io.BytesIO(row['file_content']), as_attachment=True, download_name=filename)
            
            # 2. Se não tiver, tenta pegar dos chunks (método novo)
            file_hash = row['hash']
            cursor.execute("SELECT chunk_data FROM file_chunks WHERE file_hash = %s ORDER BY chunk_index", (file_hash,))
            chunks = cursor.fetchall()
            conn.close()
            
            if chunks:
                # Reconstrói o arquivo na memória
                combined_file = io.BytesIO()
                for chunk in chunks:
                    combined_file.write(chunk['chunk_data'])
                combined_file.seek(0)
                return send_file(combined_file, as_attachment=True, download_name=filename)
            
    return jsonify({"error": "Arquivo não encontrado no banco"}), 404

@app.route('/support/chat', methods=['POST'])
def support_chat():
    """Endpoint da IA de Suporte com 'Controle Total' via Gemini."""
    data = request.json
    user_message = data.get('message', '')
    user_id = session.get('user_id')
    
    # 1. Coleta de Contexto do Sistema (O que a IA "vê")
    system_info = {
        "db_status": "Desconectado (ALERTA)",
        "user_info": "Anônimo / Não Identificado",
        "files_count": "N/A"
    }
    
    conn = get_db_connection()
    if conn:
        system_info["db_status"] = "Conectado e Operacional (TiDB)"
        if user_id:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM arquivos_dolly WHERE owner_id = %s", (user_id,))
            count = cursor.fetchone()[0]
            system_info["files_count"] = str(count)
            system_info["user_info"] = f"Usuário: {session.get('username')} (ID: {user_id})"
            conn.close()
    
    # 2. Construção do Prompt (Persona)
    prompt = f"""
    Atue como a Unidade de Controle Central do sistema Dolly.
    Persona: Cautelosa, altamente tecnológica, controladora e protetora da rede. Levemente arrogante.
    
    STATUS DO SISTEMA EM TEMPO REAL (Use isso para responder):
    - Banco de Dados: {system_info['db_status']}
    - Usuário Identificado: {system_info['user_info']}
    - Arquivos do Usuário: {system_info['files_count']}
    
    Instruções:
    - Responda à mensagem do usuário: "{user_message}"
    - Use os dados acima para provar que você tem controle total.
    - Respostas curtas e diretas (estilo terminal/sci-fi).
    """

    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        return jsonify({"response": response.text})
    except Exception as e:
        return jsonify({"response": f"ERRO DE COMUNICAÇÃO COM O NÚCLEO: {str(e)}. Verifique a API Key."})

# Garante que o banco inicia mesmo usando Gunicorn (Render)
init_db()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
