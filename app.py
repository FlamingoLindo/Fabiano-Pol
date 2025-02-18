import os

from flask import Flask, render_template, request, session

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

app = Flask(__name__)

# Chave de segurança para a sessão (aleatória)
app.secret_key = os.urandom(24)

def get_aes_key():
    """Gera ou recupera chave e IV para AES da sessão do usuário"""
    
    if 'aes_key' not in session:
        # Gera nova chave AES (128 bits) e IV (128 bits) se não existirem
        session['aes_key'] = os.urandom(16)  
        session['aes_iv'] = os.urandom(16)   
    return session['aes_key'], session['aes_iv']

@app.route('/')
def index():
    """Rota principal para renderizar a página inicial"""
    
    return render_template('index.html')

@app.route('/generate_hash', methods=['POST'])
def generate_hash():
    """Processa a geração de hash SHA-256"""
    
    password = request.form.get('hash_input') # Pega a senha do formulário
    hashed = sha256(password.encode()).hexdigest() # Gera um hash SHA-256 da senha
    return render_template('index.html', result_hash=hashed) # Renderiza a página com o hash gerado

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Realiza a criptografia AES da mensagem"""
    
    message = request.form.get('aes_input') # Pega a mensagem do formulário
    key, iv = get_aes_key() # Gera ou recupera chave e IV para AES
    
    # Configura cipher AES em modo CBC com chave e IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Criptografa mensagem com padding e codifica em Base64
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    encrypted = b64encode(ct_bytes).decode('utf-8')
    
    return render_template('index.html', encrypted_msg=encrypted) # Retorna texto cifrado

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Realiza a descriptografia AES da mensagem"""
    
    encrypted_msg = request.form.get('aes_input') # Pega a mensagem cifrada do formulário
    key, iv = get_aes_key() # Gera ou recupera chave e IV para AES
    
    try:
        # Configura cipher AES em modo CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Descriptografa e remove padding da mensagem
        pt = unpad(cipher.decrypt(b64decode(encrypted_msg)), AES.block_size)
        decrypted = pt.decode('utf-8') # Converte bytes para string
    except (ValueError, KeyError):
        decrypted = "Erro ao descriptograda a mensagem."
    
    return render_template('index.html', decrypted_msg=decrypted) # Retorna resultado

if __name__ == '__main__':
    app.run(debug=False)