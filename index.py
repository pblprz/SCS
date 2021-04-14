import os
from flask import Flask, render_template, request, send_from_directory, redirect, send_file
from werkzeug.utils import secure_filename
from secure_delete import secure_delete
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import boto3
import base64
from io import BytesIO
from dotenv import load_dotenv

app = Flask(__name__)

# AWS keys from .env
load_dotenv()
AWS_ACCESS_KEY_ID=os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY_ID=os.getenv('AWS_SECRET_ACCESS_KEY_ID')

# Variables
path = './files/'
user_password = {}
user_mode = {}
kms_client = boto3.client("kms", region_name='eu-central-1', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY_ID)
NUM_BYTES_FOR_LEN = 4

# Create directory for files if it doesn't exist
try:
    os.mkdir(path)
except:
    pass

# Create AWS key with key rotation
def create_cmk(description):
    """Creates a KMS Customer Master Key

    Description is used to differentiate between CMKs.
    """

    # Create key
    response = kms_client.create_key(Description=description)
    
    # Enable key rotation
    response2 = kms_client.enable_key_rotation(KeyId=response["KeyMetadata"]["KeyId"])

    # Return the key ID and ARN
    return response["KeyMetadata"]["KeyId"]#, response["KeyMetadata"]["Arn"]
    
def retrieve_cmk(description):
    """Retrieve an existing KMS CMK based on its description"""

    # Retrieve a list of existing CMKs
    # If more than 100 keys exist, retrieve and process them in batches
    response = kms_client.list_keys()

    for cmk in response["Keys"]:
        key_info = kms_client.describe_key(KeyId=cmk["KeyArn"])
        if key_info["KeyMetadata"]["Description"] == description:
            return cmk["KeyId"] #, cmk["KeyArn"]

    # No matching CMK found
    return None #, None
    
def create_data_key(cmk_id, key_spec="AES_256"):
    """Generate a data key to use when encrypting and decrypting data"""

    # Create data key
    response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)

    # Return the encrypted and plaintext data key
    return response["CiphertextBlob"], base64.b64encode(response["Plaintext"])

def decrypt_data_key(data_key_encrypted):
    """Decrypt an encrypted data key"""

    # Decrypt the data key
    response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response["Plaintext"]))

# Main web page (sign in)
@app.route('/')
def home():
    return render_template('signin.html')

# Display files
@app.route('/display', methods = ['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        print('name: ' + name + ' -> password: ' + password)
        try:
            # Check if password is correct and list files
            if user_password[name] == password:
                files = os.listdir(os.path.join(path, name))
                return render_template('files.html', files=files, name=name, password=password)
            else:
                return redirect('/')
        except KeyError:
            return redirect('/signup')

# Sign up
@app.route('/signup', methods = ['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        mode = request.form.get('mode')
        print('name: ' + name + ' -> password: ' + password + ' -> mode: ' + mode)
        try:
            # Sign up user if it doesn't exist
            try:
                # If user exists, redirect to sign up again
                user_password[name]
                print(name + ' already exists')
                return redirect('/signup')
            except:
                print(name + ' created')
                pass
            # Check crypto algorithm and save it (name: mode)
            if (mode == 'fernet' or mode == 'aead'):
                user_mode[name] = mode
            else:
                return redirect('/signup')
            # Save password (name: password)
            user_password[name] = password
            # Create AWS key
            temp = create_cmk(name)
            # Create directory if it doesn't exist
            try:
                os.mkdir(os.path.join(path, name))
            except:
                pass
            # If it's OK, redirect to main page (sign in)
            return redirect('/')
        except:
            # If something went wrong, redirect to sign up again
            return redirect('/signup')
    else:
        return render_template('signup.html')
	
# Upload file
@app.route('/upload', methods = ['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        f = request.files['file']
        try:
            # Check if password is correct, upload file and save it encrypted
            if user_password[name] == password:
                # Get encrypted key and key
                key_enc, key = create_data_key(retrieve_cmk(name))
                # Encrypt using Fernet
                if user_mode[name] == 'fernet':
                    fernet = Fernet(key)
                    file_enc = fernet.encrypt(f.read())
                # Encrypt using AEAD
                else:
                    derived_key_aead = HKDF(algorithm = hashes.SHA256(), length = 24, salt = None, info = None).derive(key)
                    key_aead = base64.urlsafe_b64encode(derived_key_aead)
                    aesgcm = aead.AESGCM(key_aead)
                    file_enc = aesgcm.encrypt(b"12345678", f.read(), None)
                # Save file in path
                with open(os.path.join(path + name + '/', secure_filename(f.filename)), 'wb') as file:
                    # Save encrypted key on file
                    file.write(len(key_enc).to_bytes(NUM_BYTES_FOR_LEN, byteorder='big'))
                    file.write(key_enc)
                    file.write(file_enc)
                # List files again
                files = os.listdir(os.path.join(path, name))
                return render_template('files.html', files=files, name=name, password=password)
            else:
                return redirect('/')
        except KeyError:
            return redirect('/signup')

# Download file
@app.route('/download/<filename>', methods = ['GET', 'POST'])
def upload(filename):
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        try:
            # Check if password is correct, decrypt file and download
            if user_password[name] == password:
                with open(os.path.join(path + name + '/', filename), "rb") as file:
                    file_enc = file.read()
                # Read key from file and decrypt it
                key_enc_len = int.from_bytes(file_enc[:NUM_BYTES_FOR_LEN], byteorder="big") + NUM_BYTES_FOR_LEN
                key_enc = file_enc[NUM_BYTES_FOR_LEN:key_enc_len]
                key = decrypt_data_key(key_enc)
                if user_mode[name] == 'fernet':
                    # Decrypt using Fernet
                    fernet = Fernet(key)
                    file_dec = fernet.decrypt(file_enc[key_enc_len:])
                else:
                    # Decrypt using AEAD
                    derived_key_aead = HKDF(algorithm = hashes.SHA256(), length = 24, salt = None, info = None).derive(key)
                    key_aead = base64.urlsafe_b64encode(derived_key_aead)
                    aesgcm = aead.AESGCM(key_aead)
                    file_dec = aesgcm.decrypt(b"12345678", file_enc[key_enc_len:], None)
                # Send file
                file = BytesIO(file_dec)
                return send_file(file, attachment_filename=filename)
            else:
                return redirect('/')
        except KeyError:
            return redirect('/signup')

# Delete file
@app.route('/delete/<filename>', methods = ['GET', 'POST'])
def delete(filename):
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        try:
            # Check if password is correct and delete file
            if user_password[name] == password:
                # Secure delete
                secure_delete.secure_random_seed_init()
                secure_delete.secure_delete(os.path.join(path + name + '/', filename))
                # List files again
                files = os.listdir(os.path.join(path, name))
                return render_template('files.html', files=files, name=name, password=password)
            else:
                return redirect('/')
        except KeyError:
            return redirect('/signup')
		
if __name__ == '__main__':
   app.run(debug = True)