from flask import Flask, render_template, request, redirect, url_for, send_file, session, flash
from google.cloud import storage
from werkzeug.utils import secure_filename
from flask_mysqldb import MySQL
from datetime import datetime
import bcrypt
from cryptography.fernet import Fernet
from web3 import Web3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
import hashlib
import base64
import os
import io


app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '123'
app.config['MYSQL_DB'] = '953_project'
mysql = MySQL(app)

app.secret_key = 'your_secret_key'

key = b'Sl5FZzv5YaW4oyoPLa2tz9QLmQvYm8z_IhvCUIvC9Os='
fernet = Fernet(key)

w3 = Web3(Web3.HTTPProvider("https://sepolia.infura.io/v3/eef4263821a449e582ecda1c81c4f1f1"))
private_key = "0815e6275a2ff583ace6e4d81c9905dff0222dc0d45e13f3120f2c93bd74290b"

account = w3.eth.account.from_key(private_key)
w3.eth.default_account = account.address


# Now use the checksum address to create the contract

contract_address1 = "0x3293f52f11d15212b33069f2d15024148b6774ee"
checksum_address = Web3.to_checksum_address(contract_address1)

abi1 = [
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": True,
          "internalType": "string",
          "name": "filename",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "string",
          "name": "ecdsaPublicKey",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "string",
          "name": "uploadedAt",
          "type": "string"
        }
      ],
      "name": "FileStored",
      "type": "event"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "filename",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "username",
          "type": "string"
        },
        {
          "internalType": "bytes",
          "name": "aesKey",
          "type": "bytes"
        },
        {
          "internalType": "bytes",
          "name": "encryptedData",
          "type": "bytes"
        },
        {
          "internalType": "string",
          "name": "ecdsaPublicKey",
          "type": "string"
        },
        {
          "internalType": "bytes",
          "name": "ecdsaSignature",
          "type": "bytes"
        },
        {
          "internalType": "string",
          "name": "uploadedAt",
          "type": "string"
        }
      ],
      "name": "storeFileData",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "filename",
          "type": "string"
        }
      ],
      "name": "retrieveFileMetadata",
      "outputs": [
        {
          "internalType": "bytes",
          "name": "encryptedData",
          "type": "bytes"
        },
        {
          "internalType": "string",
          "name": "ecdsaPublicKey",
          "type": "string"
        },
        {
          "internalType": "bytes",
          "name": "ecdsaSignature",
          "type": "bytes"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "filename",
          "type": "string"
        }
      ],
      "name": "retrieveFileAndKey",
      "outputs": [
        {
          "internalType": "bytes",
          "name": "encryptedData",
          "type": "bytes"
        },
        {
          "internalType": "bytes",
          "name": "aesKey",
          "type": "bytes"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    }
  ]

contract_address2 = "0x1F569193670ad2FdcC1bD1600f771Cdef096Bc3A"
abi2 = [
    {
      "inputs": [],
      "name": "filename",
      "outputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [],
      "name": "owner",
      "outputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [],
      "name": "requestTime",
      "outputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [],
      "name": "requester",
      "outputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [],
      "name": "status",
      "outputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "_filename",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "_requester",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "_owner",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "_requestTime",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "_status",
          "type": "string"
        }
      ],
      "name": "storeAccess",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
  ]

contract1 = w3.eth.contract(address=checksum_address, abi=abi1)
contract2 = w3.eth.contract(address=contract_address2, abi=abi2)


UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def encrypt_file(file_data, key):
    iv = os.urandom(16)  # Random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_file(encrypted_data, key):
    # The first 16 bytes are the IV
    iv = encrypted_data[:16]
    actual_encrypted_data = encrypted_data[16:]
    
    # Create a cipher object for decryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
    return decrypted_data

def sign_data(ecdsa_private_key, data):
    signature = ecdsa_private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(ecdsa_public_key_pem, data, signature):
    try:
        # Deserialize the PEM-formatted public key bytes
        ecdsa_public_key = load_pem_public_key(ecdsa_public_key_pem)

        # Verify the signature
        ecdsa_public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True  # Signature is valid
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Verification error: {e}")
        return False

# Set up Google Cloud Storage client
def create_storage_client():
    return storage.Client.from_service_account_json('client_key.json')

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT username, password FROM user_info WHERE username = %s OR password = %s', (username, password))
        existing_user = cursor.fetchone()
        if existing_user:
            if existing_user[0] == username:
                flash(f'Username already exists!')
        else:
            cursor.execute('INSERT INTO user_info (username, password) VALUES (%s, %s)', (username, password))
            mysql.connection.commit()
            cursor.close()
            return redirect(url_for('register_user'))

    return render_template('register.html')


@app.route('/login_user', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT username, password FROM user_info WHERE username = %s', (username,))
        user_info = cursor.fetchone()
        cursor.close()

        if user_info:
            db_username, db_password = user_info
            if bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8')):
                session['username'] = username  
                return redirect(url_for('list_files'))
            else:
                password_error = 'Password is incorrect!'
        else:
            username_error = 'Username does not exist!'

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_user'))


@app.route('/')
def list_files():
    username = session.get('username')
    storage_client = create_storage_client()
    bucket_name = 'bucket-quickstart_cellular-deck-438900-m7'  
    bucket = storage_client.bucket(bucket_name)
    blobs = bucket.list_blobs()
    file_list = [blob.name for blob in blobs]

    if file_list:
        placeholders = ', '.join(['%s'] * len(file_list))
        query = f'SELECT filename, owner, uploaded_at FROM file_info WHERE filename IN ({placeholders})'
        cursor = mysql.connection.cursor()
        cursor.execute(query, file_list)
        owners_and_times = cursor.fetchall()
        cursor.close()
        
        owner_time_dict = {
            filename: {'owner': owner, 'uploaded_at': uploaded_at}
            for filename, owner, uploaded_at in owners_and_times
        }
    else:
        owner_time_dict = {}
    return render_template('index.html', files=file_list, username=username, owner_time=owner_time_dict)


@app.route('/encrypt_sign', methods=['POST'])
def encrypt_and_sign():
    if 'username' not in session:
        return redirect(url_for('login_user'))

    username = session.get('username')

    if 'file' not in request.files:
        flash(f'No file provided')
    
    file = request.files['file']
    
    if file.filename == '':
        flash(f'No file selected')
    
    file_data = file.read()

    aes_key = os.urandom(32)
    encrypted_data = encrypt_file(file_data, aes_key)
    ecdsa_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdsa_public_key = ecdsa_private_key.public_key()
    signature = sign_data(ecdsa_private_key, encrypted_data)
    enc_key = fernet.encrypt(aes_key.encode())

    if encrypted_data:
        filename = secure_filename(file.filename)
        storage_client = create_storage_client()
        bucket_name = 'bucket-quickstart_cellular-deck-438900-m7'
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(filename)

        encrypted_file_io = io.BytesIO(encrypted_data)

        uploaded_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        pem_ecdsa_public_key = ecdsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ecdsa_public_key_str = pem_ecdsa_public_key.decode('utf-8')
        try:
            gas_estimate = contract1.functions.storeFileData(filename, username, aes_key, encrypted_data, ecdsa_public_key_str, signature, uploaded_at).estimate_gas({
                'from': w3.eth.default_account,
                'nonce': w3.eth.get_transaction_count(w3.eth.default_account),
            })

            transaction = contract1.functions.storeFileData(filename, username, enc_key, encrypted_data, ecdsa_public_key_str, signature, uploaded_at).build_transaction({
                'from': w3.eth.default_account,
                'nonce': w3.eth.get_transaction_count(w3.eth.default_account),
                'gas': gas_estimate, 
                'gasPrice': w3.to_wei('5', 'gwei'),
            })

            signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

            if tx_receipt.status == 1:
                blob.upload_from_file(encrypted_file_io)
                cursor = mysql.connection.cursor()
                cursor.execute('INSERT INTO file_info (filename, owner, aes_key, encrypted_file, signature, ecdsa_public_key, ecdsa_private_key, uploaded_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)', 
                                (filename, username, aes_key, encrypted_data, signature, ecdsa_public_key_str, ecdsa_private_key, uploaded_at))
                mysql.connection.commit()
                cursor.close()

                flash(f"{filename} has been encrypted and uploaded successfully with hash: {tx_hash.hex()}")
            else:
                revert_reason = w3.eth.get_transaction_receipt(tx_hash).logs[0].data
                flash(f"Transaction failed: {revert_reason.hex()}")

        except Exception as e:
            print(f"Transaction failed: {e}")
            return redirect('/')

    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename + ".enc")
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    return redirect(url_for('list_files'))

@app.route('/request_file', methods=['POST'])
def request_file():
    if 'username' not in session:
        return redirect(url_for('login_user'))

    username = session.get('username')
    filename = request.form.get('filename')

    if not filename:
        flash('No filename provided!')
        return redirect(url_for('list_files'))

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT owner FROM file_info WHERE filename = %s', (filename,))
    owner = cursor.fetchone()
    owner = owner[0]

    requester = username  
    request_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('INSERT INTO request_info (filename, requester, owner, request_time, status) VALUES (%s, %s, %s, %s, %s)',
                   (filename, requester, owner, request_time, 'Pending'))
    mysql.connection.commit()
    cursor.close()

    try:
        transaction_params = contract2.functions.storeAccess('Filename: ' + filename, 'Requester: ' + requester, 'Owner: ' + owner, 'Request Time: ' + request_time, 'Status: ' + 'Pending').build_transaction({
            'from': w3.eth.default_account,
            'gas': 3000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(w3.eth.default_account),
        })

        signed_transaction = w3.eth.account.sign_transaction(transaction_params, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if tx_receipt.status == 1:
            stored_filename = contract2.functions.filename().call()
            stored_requester = contract2.functions.requester().call()
            stored_owner = contract2.functions.owner().call()
            stored_request_time = contract2.functions.requestTime().call()
            flash(f"Download request for {filename} sent with transaction hash: {tx_hash.hex()}")
        else:
            flash("Transaction failed")

    except Exception as e:
        flash(f"Transaction failed with error: {str(e)}")

    return redirect(url_for('list_files'))

@app.route('/view_download')
def view_download():
    requester = session.get('username')
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM request_info WHERE requester = %s', (requester,))
    downloads = cursor.fetchall()
    cursor.close()
    return render_template('view_download.html', downloads=downloads)

@app.route('/view_request')
def view_request():
    owner = session.get('username')
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM request_info WHERE owner = %s', (owner,))
    requests = cursor.fetchall()
    cursor.close()
    return render_template('view_request.html', requests=requests)

@app.route('/approve_request/<int:request_id>', methods=['POST'])
def approve_request(request_id):
    cursor = mysql.connection.cursor()
    
    cursor.execute("UPDATE request_info SET status = 'Approved' WHERE request_id = %s", (request_id,))
    mysql.connection.commit()

    cursor.execute("SELECT * FROM request_info WHERE request_id = %s", (request_id,))
    updated_row = cursor.fetchone() 
    cursor.close()

    try:
        transaction_params = contract2.functions.storeAccess('Filename: ' + updated_row[1], 'Requester: ' + updated_row[2], 'Owner: ' + updated_row[3], 'Request Time: ' + str(updated_row[4]), 'Status: ' + updated_row[5]).build_transaction({
            'from': w3.eth.default_account,
            'gas': 3000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(w3.eth.default_account),
        })

        signed_transaction = w3.eth.account.sign_transaction(transaction_params, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if tx_receipt.status == 1:
            flash(f"Request for {updated_row[1]} has been approved with transaction hash: {tx_hash.hex()}")
        else:
            flash("Transaction failed")

    except Exception as e:
        flash(f"Transaction failed with error: {str(e)}")

    return redirect(url_for('view_request'))


@app.route('/deny_request/<int:request_id>', methods=['POST'])
def deny_request(request_id):
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE request_info SET status = 'Denied' WHERE request_id = %s", (request_id,))
    mysql.connection.commit()

    cursor.execute("SELECT * FROM request_info WHERE request_id = %s", (request_id,))
    updated_row = cursor.fetchone() 
    cursor.close()
    cursor.close()

    try:
        # inputData = updated_row[1] + ', ' + updated_row[2] + ', ' + updated_row[3] + ', ' + str(updated_row[4]) + ', ' + updated_row[5]
        transaction_params = contract2.functions.storeAccess('Filename: ' + updated_row[1], 'Requester: ' + updated_row[2], 'Owner: ' + updated_row[3], 'Request Time: ' + str(updated_row[4]), 'Status: ' + updated_row[5]).build_transaction({
            'from': w3.eth.default_account,
            'gas': 3000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(w3.eth.default_account),
        })

        signed_transaction = w3.eth.account.sign_transaction(transaction_params, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        if tx_receipt.status == 1:
            flash(f"Request for {updated_row[1]} has been denied with transaction hash: {tx_hash.hex()}")
        else:
            flash("Transaction failed")
            
    except Exception as e:
        flash(f"Transaction failed with error: {str(e)}")

    return redirect(url_for('view_request'))


@app.route('/verify_and_decrypt', methods=['GET', 'POST'])
def verify_and_decrypt():
    filename = request.form.get('file')
    if filename == '':
        flash('No file or signature selected for verification')
        return redirect(url_for('view_download'))

    encrypted_data_a, ecdsa_public_key, signature = contract1.functions.retrieveFileMetadata(filename).call()
    ecdsa_public_key_verify = serialization.load_pem_public_key(ecdsa_public_key.encode('utf-8'), backend=default_backend())
    is_valid = verify_signature(ecdsa_public_key_verify, encrypted_data_a, signature)
    encrypted_data, aes_key = contract1.functions.retrieveFileAndKey(filename).call()
    dec_aes_key = fernet.decrypt(aes_key).decode()
    decrypted_data = decrypt_file(encrypted_data_a, dec_aes_key)
    decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + ".dec")
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    flash('File decrypted and downloaded successfully!')

    return redirect(url_for('view_download'))

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    storage_client = create_storage_client()
    bucket_name = 'bucket-quickstart_cellular-deck-438900-m7'
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(filename)

    # Delete the file
    blob.delete()
    flash(f'File "{filename}" deleted successfully!')
    return redirect(url_for('list_files'))

if __name__ == '__main__':
    app.run(debug=True)
