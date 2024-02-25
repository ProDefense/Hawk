from flask import Flask, request

app = Flask(__name__)


@app.route('/', methods=['GET'])
def receive_payload():
    username = request.args.get('username')
    password = request.args.get('password')
    hostname = request.args.get('hostname')

    if username and password and hostname:
        print(f"Received payload - Username: {username}, Password: {password}, Hostname: {hostname}")
        return '', 200
    else:
        return 'Invalid payload', 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6969)