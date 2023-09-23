from flask import Flask, request, send_from_directory
from pathlib import Path
import json
import re


app = Flask(__name__, static_url_path='/')

@app.route('/')
def index():
    return send_from_directory('./static/', 'index.html')


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not re.match('^[a-zA-Z0-9]{,32}$', data['user']):
        return 'Invalid username', 400
    try:
        userdir = Path('data/user').with_name(data['user'])
        userdir.mkdir()
        with (userdir / 'params').open('w') as f:
            f.write(json.dumps(data['pubkey']))
        return 'OK'
    except FileExistsError:
        return 'User already exists', 400


@app.route('/pubkey/<user>', methods=['GET'])
def pubkey(user):
    try:
        userdir = Path('data/user').with_name(user)
        with (userdir / 'params').open('r') as f:
            return f.read()
    except FileNotFoundError:
        return 'User does not exist', 404


@app.route('/send/<user>', methods=['POST'])
def sendmessage(user):
    try:
        userdir = Path('data/user').with_name(user)
        with (userdir / 'inbox').open('a') as f:
            msg = request.get_data().decode()
            if not re.match('^[0-9a-f]{,4096}$', msg):
                return 'Invalid message', 400
            f.write(msg + '\n')
        return 'OK'
    except FileNotFoundError:
        return 'User does not exist', 404
    except PermissionError:
        return 'User mailbox has been disabled', 403


@app.route('/disable/<user>', methods=['POST'])
def disable(user):
    try:
        userdir = Path('data/user').with_name(user)
        with (userdir / 'params').open('r') as f:
            pubkey = json.loads(f.read())
        n = int(pubkey[0], 16)
        e = int(pubkey[1], 16)

        try:
            data = request.get_data().decode()
            chall = int(data, 16)
        except ValueError:
            return 'Invalid challenge', 400

        if pow(chall, e, n) == 0xbadf00d:
            (userdir / 'inbox').chmod(0o400)
            return 'OK'
        else:
            return 'Invalid challenge', 400
    except FileNotFoundError:
        return 'User does not exist', 404


@app.route('/inbox/<user>', methods=['GET'])
def inbox(user):
    try:
        userdir = Path('data/user').with_name(user)
        with (userdir / 'inbox').open('r') as f:
            return json.dumps(f.read().split('\n')[:-1])
    except FileNotFoundError:
        return '[]'


if __name__ == '__main__':
    app.run()
