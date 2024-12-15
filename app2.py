from flask import Flask, render_template, request, redirect, url_for, flash, make_response
import json
import os
import hashlib  # For password hashing

app = Flask(__name__)
app.secret_key = 'hanishsai'  # Secret key for flash messages

# File to store user data
DATA_FILE = 'data.json'

# Load users from the JSON file
def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return []

# Save users to the JSON file
def save_users(users):
    with open(DATA_FILE, 'w') as f:
        json.dump(users, f)

# Hash password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Home route to add a user
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        age = request.form['age']
        password = request.form['password']
        
        # Hash the password
        hashed_password = hash_password(password)

        # Load existing users
        users = load_users()
        user_id = len(users) + 1  # Simple user id generation

        # Create new user
        new_user = {
            'id': user_id,
            'name': name,
            'email': email,
            'age': age,
            'password': hashed_password
        }
        users.append(new_user)

        # Save updated user list
        save_users(users)
        
        # Set a secure cookie
        resp = make_response(redirect(url_for('users')))
        resp.set_cookie('session_id', str(user_id), secure=True, httponly=True, samesite='Strict', max_age=60*60*24)
        flash('User added successfully!', 'success')
        return resp

    return render_template('index6.html')

# User list page
@app.route('/users')
def users():
    session_id = request.cookies.get('session_id')
    if not session_id:
        flash('Please add a user to start a session.', 'danger')
        return redirect(url_for('index'))
    
    users = load_users()
    return render_template('users6.html', users=users)

# Edit user page
@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    session_id = request.cookies.get('session_id')
    if not session_id or int(session_id) != user_id:
        flash('Unauthorized access. Please log in first.', 'danger')
        return redirect(url_for('index'))

    users = load_users()
    user = next((u for u in users if u['id'] == user_id), None)

    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('users'))

    if request.method == 'POST':
        user['name'] = request.form['name']
        user['email'] = request.form['email']
        user['age'] = request.form['age']
        save_users(users)
        flash('User updated successfully!', 'success')
        return redirect(url_for('users'))

    return render_template('edit6.html', user=user)

# Delete user
@app.route('/delete/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    session_id = request.cookies.get('session_id')
    if not session_id or int(session_id) != user_id:
        flash('Unauthorized access. Please log in first.', 'danger')
        return redirect(url_for('index'))

    users = load_users()
    user = next((u for u in users if u['id'] == user_id), None)

    if user:
        users.remove(user)
        save_users(users)
        flash('User deleted successfully!', 'success')

    return redirect(url_for('users'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Hash the password
        hashed_password = hash_password(password)

        # Load users and check credentials
        users = load_users()
        user = next((u for u in users if u['email'] == email), None)

        if user and user['password'] == hashed_password:
            # Set a secure cookie
            resp = make_response(redirect(url_for('users')))
            resp.set_cookie('session_id', str(user['id']), secure=True, httponly=True, samesite='Strict', max_age=60*60*24)
            flash('Login successful!', 'success')
            return resp
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login6.html')

# Logout and clear cookie
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('session_id', '', expires=0)  # Clear the cookie
    flash('Logged out successfully!', 'success')
    return resp

if __name__ == '__main__':
    app.run(debug=True)
