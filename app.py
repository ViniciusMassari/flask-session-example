from flask import Flask, jsonify, request
from models.user import User
from database import db
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from bcrypt import hashpw, gensalt, checkpw


app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.post('/login')
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and checkpw(str.encode(password), user.password):
            login_user(user)
            return jsonify({"message": "Autenticação feita com sucesso"})

    return jsonify({"message:": "Credenciais inválidas"}), 400


@app.post("/logout")
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})


@app.post("/create_user")
def create_user():
    user = request.get_json()
    username = user['username']
    password = user['password']

    if username and password:
        hashed_password = hashpw(str.encode(password), gensalt())
        new_user = User(username=username, password=hashed_password,
                        role="user")  # type: ignore
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created"}), 201

    return jsonify({"message": "Dados inválidos"}), 400


@app.get("/user/<int:user_id>")
@login_required
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"username": user.username})
    return jsonify({"Message": "User not found"}), 404


@app.put("/user/<int:user_id>")
@login_required
def update_user(user_id):
    data = request.get_json()
    user = User.query.get(user_id)
    if user_id != int(current_user.get_id()) and current_user.role == "user":
        return jsonify({"message": "Você não está autorizado a atualizar este dado"}), 403
    if user:
        user.password = data["password"]
        db.session.commit()
        return jsonify({"message": "Usuário atualizado com sucesso"})
    return jsonify({"Message": "User not found"}), 404


@app.delete("/user/<int:user_id>")
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if current_user.role != 'admin':
        return jsonify({"message": "Operação não permitida"}), 403

    if user_id != int(current_user.get_id()):
        return jsonify({"message": "Você não está autorizado a remover este dado"})

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "Usuário deletado com sucesso"})
    return jsonify({"Message": "User not found"}), 404


if __name__ == '__main__':
    app.run(debug=True)
