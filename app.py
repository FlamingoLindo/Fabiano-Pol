import os

from flask import Flask, render_template, request, session

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

app = Flask(__name__)

app.secret_key = os.urandom(24)

def get_aes_key():
    if 'aes_key' not in session:
        session['aes_key'] = os.urandom(16)  
        session['aes_iv'] = os.urandom(16)   
    return session['aes_key'], session['aes_iv']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_hash', methods=['POST'])
def generate_hash():
    password = request.form.get('hash_input')
    hashed = sha256(password.encode()).hexdigest()
    return render_template('index.html', result_hash=hashed)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form.get('aes_input')
    key, iv = get_aes_key()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    encrypted = b64encode(ct_bytes).decode('utf-8')
    
    return render_template('index.html', encrypted_msg=encrypted)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_msg = request.form.get('aes_input')
    key, iv = get_aes_key()
    
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(b64decode(encrypted_msg)), AES.block_size)
        decrypted = pt.decode('utf-8')
    except (ValueError, KeyError):
        decrypted = "Decryption Error!"
    
    return render_template('index.html', decrypted_msg=decrypted)

if __name__ == '__main__':
    app.run(debug=False)