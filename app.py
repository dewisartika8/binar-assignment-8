from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from flasgger import Swagger, swag_from

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['SWAGGER'] = {
    'title': 'To-Do List API',
    'uiversion': 3
}
db = SQLAlchemy(app)
jwt = JWTManager(app)

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "To-Do List API",
        "description": "API documentation for To-Do List with JWT Auth",
        "version": "1.0"
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Bearer <token>"
        }
    }
}

swagger = Swagger(app, template=swagger_template)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    is_done = db.Column(db.Boolean, default=False)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'), nullable=False)

# Auth Endpoints
@app.route('/api/register', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['email', 'password']
            }
        }
    ],
    'responses': {
        201: {'description': 'User registered'},
        400: {'description': 'Email already registered'}
    }
})
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'msg': 'Email already registered'}), 400
    hashed = generate_password_hash(data['password'], method='pbkdf2:sha256')
    user = User(email=data['email'], password=hashed)
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'User registered'}), 201

@app.route('/api/login', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['email', 'password']
            }
        }
    ],
    'responses': {
        200: {'description': 'Login success, return token'},
        401: {'description': 'Invalid credentials'}
    }
})
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'msg': 'Invalid credentials'}), 401
    token = create_access_token(identity=user.id)
    return jsonify({'token': token}), 200

# Lists Endpoints
@app.route('/api/lists', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Lists'],
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {'description': 'List of user\'s lists'}
    }
})
def get_lists():
    user_id = get_jwt_identity()
    lists = List.query.filter_by(user_id=user_id).all()
    return jsonify([{'id': l.id, 'name': l.name} for l in lists])

@app.route('/api/lists', methods=['POST'])
@jwt_required()
@swag_from({
    'tags': ['Lists'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string', 'example': 'Belanja'}
                },
                'required': ['name']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'List created',
            'examples': {
                'application/json': {
                    'id': 1,
                    'name': 'Belanja'
                }
            }
        }
    }
})
def create_list():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_list = List(name=data['name'], user_id=user_id)
    db.session.add(new_list)
    db.session.commit()
    return jsonify({'id': new_list.id, 'name': new_list.name}), 201

@app.route('/api/lists/<int:list_id>', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['Lists'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'list_id',
            'in': 'path',
            'required': True,
            'type': 'integer'
        },
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'}
                },
                'required': ['name']
            }
        }
    ],
    'responses': {
        200: {'description': 'List updated'},
        404: {'description': 'List not found'}
    }
})
def update_list(list_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    l = List.query.filter_by(id=list_id, user_id=user_id).first_or_404()
    l.name = data['name']
    db.session.commit()
    return jsonify({'id': l.id, 'name': l.name})

@app.route('/api/lists/<int:list_id>', methods=['DELETE'])
@jwt_required()
@swag_from({
    'tags': ['Lists'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'list_id',
            'in': 'path',
            'required': True,
            'type': 'integer'
        }
    ],
    'responses': {
        200: {'description': 'List deleted'},
        404: {'description': 'List not found'}
    }
})
def delete_list(list_id):
    user_id = get_jwt_identity()
    l = List.query.filter_by(id=list_id, user_id=user_id).first_or_404()
    db.session.delete(l)
    db.session.commit()
    return jsonify({'msg': 'List deleted'})

# Tasks Endpoints
@app.route('/api/lists/<int:list_id>/tasks', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Tasks'],
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {'description': 'List of tasks in the list'}
    }
})
def get_tasks(list_id):
    user_id = get_jwt_identity()
    l = List.query.filter_by(id=list_id, user_id=user_id).first_or_404()
    tasks = Task.query.filter_by(list_id=l.id).all()
    return jsonify([{'id': t.id, 'description': t.description, 'is_done': t.is_done} for t in tasks])

@app.route('/api/lists/<int:list_id>/tasks', methods=['POST'])
@jwt_required()
@swag_from({
    'tags': ['Tasks'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'description': {'type': 'string'}
                },
                'required': ['description']
            }
        }
    ],
    'responses': {
        201: {'description': 'Task created'}
    }
})
def create_task(list_id):
    user_id = get_jwt_identity()
    l = List.query.filter_by(id=list_id, user_id=user_id).first_or_404()
    data = request.get_json()
    task = Task(description=data['description'], is_done=False, list_id=l.id)
    db.session.add(task)
    db.session.commit()
    return jsonify({'id': task.id, 'description': task.description, 'is_done': task.is_done}), 201

@app.route('/api/lists/<int:list_id>/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['Tasks'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'list_id',
            'in': 'path',
            'required': True,
            'type': 'integer'
        },
        {
            'name': 'task_id',
            'in': 'path',
            'required': True,
            'type': 'integer'
        },
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'description': {'type': 'string'},
                    'is_done': {'type': 'boolean'}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'Task updated'},
        404: {'description': 'Task not found'}
    }
})
def update_task(list_id, task_id):
    user_id = get_jwt_identity()
    l = List.query.filter_by(id=list_id, user_id=user_id).first_or_404()
    task = Task.query.filter_by(id=task_id, list_id=l.id).first_or_404()
    data = request.get_json()
    task.description = data.get('description', task.description)
    task.is_done = data.get('is_done', task.is_done)
    db.session.commit()
    return jsonify({'id': task.id, 'description': task.description, 'is_done': task.is_done})

@app.route('/api/lists/<int:list_id>/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
@swag_from({
    'tags': ['Tasks'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'list_id',
            'in': 'path',
            'required': True,
            'type': 'integer'
        },
        {
            'name': 'task_id',
            'in': 'path',
            'required': True,
            'type': 'integer'
        }
    ],
    'responses': {
        200: {'description': 'Task deleted'},
        404: {'description': 'Task not found'}
    }
})
def delete_task(list_id, task_id):
    user_id = get_jwt_identity()
    l = List.query.filter_by(id=list_id, user_id=user_id).first_or_404()
    task = Task.query.filter_by(id=task_id, list_id=l.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    return jsonify({'msg': 'Task deleted'})

@app.route('/ping')
def ping():
    """
    Test endpoint
    ---
    responses:
      200:
        description: pong
    """
    return "pong"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5001)