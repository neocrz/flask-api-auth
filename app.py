from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# in-memory user database
users = {}

@app.route('/signup', methods=['POST'])
def signup():
    username = request.json['username']
    password = request.json['password']

    if username in users:
        return jsonify({'error': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users[username] = {'password': hashed_password}  # store hashed password

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    if username not in users:
        return jsonify({'error': 'Invalid username or password'}), 401

    if not bcrypt.check_password_hash(users[username]['password'], password):
        return jsonify({'error': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=username)  # Generate JWT
    return jsonify({'access_token': access_token}), 200

@app.route('/protected_resource', methods=['GET'])
@jwt_required()
def protected_resource():
    current_user = get_jwt_identity()  # Access user information from JWT
    return jsonify({'message': f'Welcome, {current_user}!'}), 200

if __name__ == '__main__':
    app.run(debug=True)
