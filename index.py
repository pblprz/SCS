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
from io import StringIO, BytesIO
from dotenv import load_dotenv

load_dotenv()

AWS_ACCESS_KEY_ID=os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY_ID=os.getenv('AWS_SECRET_ACCESS_KEY_ID')

app = Flask(__name__)
path = './unsecure/'
user_password = {}
user_mode = {}
user_key = {}

#kms_client = boto3.client("kms", region_name='eu-central-1', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY_ID)

def create_cmk(description):
    """Creates a KMS Customer Master Key

    Description is used to differentiate between CMKs.
    """

    response = kms_client.create_key(Description=description)
    
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
            return cmk["KeyId"]#, cmk["KeyArn"]

    # No matching CMK found
    return None#, None
    
def create_data_key(cmk_id, key_spec="AES_256"):
    """Generate a data key to use when encrypting and decrypting data"""

    # Create data key
    response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)

    # Return the encrypted and plaintext data key
    #return response["CiphertextBlob"], base64.b64encode(response["Plaintext"])
    return base64.b64encode(response["Plaintext"])
    
def decrypt_data_key(data_key_encrypted):
    """Decrypt an encrypted data key"""

    # Decrypt the data key
    response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response["Plaintext"]))
    
def encrypt_file(file, key):
    """Encrypt JSON data using an AWS KMS CMK"""

    # Encrypt the data
    f = Fernet(key)
    file_encrypted = f.encrypt(file)

    return file_encrypted
    
def decrypt_file(file, key):
    """Decrypt a file encrypted by encrypt_file()"""

    # Decrypt the rest of the file
    f = Fernet(key)
    file_decrypted = f.decrypt(file)

    return file_decrypted

@app.route('/')
def home():
    return render_template('signin.html')

@app.route('/display', methods = ['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        print('name: ' + name + ' -> password: ' + password)
        try:
            if user_password[name] == password:
                files = os.listdir(os.path.join(path, name))
                return render_template('files.html', files=files, name=name, password=password)
            else:
                return redirect('/')
        except KeyError:
            return redirect('/signup')

@app.route('/signup', methods = ['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        mode = request.form.get('mode')
        print('name: ' + name + ' -> password: ' + password + ' -> mode: ' + mode)
        try:
            if (mode == 'fernet' or mode == 'aead'):
                user_mode[name] = mode
            else:
                return redirect('/signup')
            user_password[name] = password
            key = base64.urlsafe_b64encode(os.urandom(32))
            #key = create_data_key(create_cmk(name))
            user_key[name] = key
            try:
                os.mkdir(os.path.join(path, name))
            except:
                pass
            return redirect('/')
        except:
            return redirect('/signup')
    else:
        return render_template('signup.html')
	
@app.route('/upload', methods = ['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        f = request.files['file']
        try:
            if user_password[name] == password:
                key = user_key[name]
                if user_mode[name] == 'fernet':
                    fernet = Fernet(key)
                    file_enc = fernet.encrypt(f.read())
                else:
                    derived_key_aead = HKDF(algorithm = hashes.SHA256(), length = 24, salt = None, info = None).derive(key)
                    key_aead = base64.urlsafe_b64encode(derived_key_aead)
                    aesgcm = aead.AESGCM(key_aead)
                    file_enc = aesgcm.encrypt(b"12345678", f.read(), None)
                with open(os.path.join(path + name + '/', secure_filename(f.filename)), 'wb') as file:
                    file.write(file_enc) 
                # f.save(os.path.join(path + name + '/', secure_filename(f.filename)))
                files = os.listdir(os.path.join(path, name))
                return render_template('files.html', files=files, name=name, password=password)
            else:
                return redirect('/')
        except KeyError:
            return redirect('/signup')

@app.route('/download/<filename>', methods = ['GET', 'POST'])
def upload(filename):
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        try:
            if user_password[name] == password:
                with open(os.path.join(path + name + '/', filename), "rb") as file:
                    file_enc = file.read()
                key = user_key[name]
                if user_mode[name] == 'fernet':
                    fernet = Fernet(key)
                    file_dec = fernet.decrypt(file_enc)
                else:
                    derived_key_aead = HKDF(algorithm = hashes.SHA256(), length = 24, salt = None, info = None).derive(key)
                    key_aead = base64.urlsafe_b64encode(derived_key_aead)
                    aesgcm = aead.AESGCM(key_aead)
                    file_dec = aesgcm.decrypt(b"12345678", file_enc, None)
                file = BytesIO(file_dec)
                return send_file(file, attachment_filename=filename)
                #return send_from_directory(os.path.join(path, name), filename)
            else:
                return redirect('/')
        except KeyError:
            return redirect('/signup')

@app.route('/delete/<filename>', methods = ['GET', 'POST'])
def delete(filename):
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        try:
            if user_password[name] == password:
                secure_delete.secure_random_seed_init()
                secure_delete.secure_delete(os.path.join(path + name + '/', filename))
                files = os.listdir(os.path.join(path, name))
                return render_template('files.html', files=files, name=name, password=password)
            else:
                return redirect('/')
        except KeyError:
            return redirect('/signup')
		
if __name__ == '__main__':
   app.run(debug = True)