from flask import Flask,render_template,request,session, redirect,jsonify,make_response,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import re
import requests




app = Flask(__name__)
app.secret_key = "b'?|p_TF\xfd\x0e\xc7\xc3\x1c-\xfc\xf0\x07\x9c\xe0\xc7\xe3\xb6(\xcc-\xd1'"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///contacts.db"
app.config['JWT_SECRET_KEY'] = '54c01e0fb1a1b53f22066eeda7d3a798082d2d342043608c58aa00ec31925242'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


def validate_data(data):
    if not data.get('name'):
        return  "name cannot be blank"
    if not data.get('email') or not is_valid_email(data.get('email')):
        return "Invalid email address"
    if not data.get('password'):
        return "Password cannot be blank"
    return None

def is_valid_email(email):
    # regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$'
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    if re.match(regex, email):
        return True
    else:
        return False


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    contacts = db.relationship('Contact', backref='owner', lazy=True)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=True)
    country = db.Column(db.String(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route("/user/login",methods=["POST"])
def login():
        data = request.get_json()
        email = data.get('email')
        email = data.get('email')
        password = data.get('password')
        if not data.get('email') or not is_valid_email(data.get('email')):
            return jsonify({'message': 'Invalid email', 'data': {}}), 400
        if not data.get('password'):
            return jsonify({'message': 'Password cannot be left blank', 'data': {}}), 400
    
        if User.query.filter_by(email=email).first():
            user = User.query.filter_by(email=email).first()
            pwd = user.password
            if user and bcrypt.check_password_hash(pwd, password):
                access_token = create_access_token(identity=user.email)
                # url = 'http://127.0.0.1:8000/user'
                # headers = {"Authorization":"Bearer " + access_token}
                # response = requests.get('http://127.0.0.1:8000/user',headers=headers)
                # print (response)
                # decoded = jwt1.decode(access_token, "54c01e0fb1a1b53f22066eeda7d3a798082d2d342043608c58aa00ec31925242", algorithms=["HS256"])
                # print(decoded)
                # response = make_response(redirect(url_for("user")))
                # response.headers['Authorization'] = f'Bearer {access_token}'
                # session['access_token'] = access_token
                # session['email'] = email
                # session['id'] = user.id
                # return f'Logged in as {session["access_token"]}'   
                return {
                            
                            "message" : "Login successful",
                            "data": {
                                "access_token": access_token,
                                "user": {
                                    "id": user.id,
                                    "name": user.name,
                                    "email": user.email
                                }
                            }
                        },200
            else:
                return{
                        "message" : "Invalid credentials",
                        "data": {}

                    },401
            

        
@app.route('/user')
@jwt_required()
def user():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({'message': 'User not found', 'data': {}}), 404
    return {
        
        "id": user.id,
        "name": user.name,
        "email " : user.email
    }

@app.route('/contact', methods=['POST'])
@jwt_required()
def add_contact():
    data = request.get_json()
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()
    
    if not user:
        return jsonify({'message': 'User not found', 'data': {}}), 404
    name = data.get('name')
    phone = data.get('phone')
    if not name:
        return jsonify({'message': 'Name is required', 'data': {}}), 400
    if not phone:
        return jsonify({'message': 'Phone is required', 'data': {}}), 400
    email = data.get('email')
    address = data.get('address',"")
    country = data.get('country',"")

    if email and not is_valid_email(email):
        return jsonify({'message': 'Invalid email', 'data': {}}), 400
    
    contact = Contact(
        name= name, email=email, phone=phone,
        address=address, country=country, owner=user
    )
    db.session.add(contact)
    db.session.commit()
    
    return jsonify({
        'message': 'Contact added',
        'data': {
            'id': contact.id, 'name': contact.name, 'email': contact.email,
            'phone': contact.phone, 'country': contact.country, 'address': contact.address
        }
    }), 200

@app.route('/contact', methods=['GET'])
@jwt_required()
def list_contacts():
    user_email = get_jwt_identity() 
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found', 'data': {}}), 404
    user_id=user.id
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    sort_by = request.args.get('sort_by', 'latest')

    query = Contact.query.filter_by(user_id=user_id)
    query = Contact.query.filter_by(user_id=user_id)

    if sort_by == 'latest':
        query = query.order_by(Contact.id.desc())
    elif sort_by == 'oldest':
        query = query.order_by(Contact.id.asc())
    elif sort_by == 'alphabetically_a_to_z':
        query = query.order_by(Contact.name.asc())
    elif sort_by == 'alphabetically_z_to_a':
        query = query.order_by(Contact.name.desc())

    pagination = query.paginate(page=page, per_page=limit)
    contacts = pagination.items
    
    return jsonify({
        'message': 'Contact list',
        'data': {
            'list': [{'id': c.id,
                      'name': c.name, 
                      'email': c.email, 
                      'phone': c.phone, 
                      'country': c.country, 
                      'address': c.address
                      } for c in contacts],
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page,
            'total': pagination.total
        }
    }), 200

@app.route('/contact/search', methods=['GET'])
# @jwt_required()
def search_contacts():
    # id = get_jwt_identity()
    # print(id)
    user_id = session['id']
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found', 'data': {}}), 404
    if not user_id:
        return {
            'message': 'please Login First',
            'data': {}
        },404
    query = Contact.query.filter_by(id=user_id)
    name = request.args.get('name')
    
    if name:
        query = query.filter(Contact.name.like(f"%{name}%"))
    if request.args.get('email'):
        query = query.filter(Contact.email.like(f"%{request.args.get('email')}%"))
    if request.args.get('phone'):
        query = query.filter(Contact.phone.like(f"%{request.args.get('phone')}%"))
    
    contacts = query.all()
    return jsonify({
        'message': 'Search results',
        'data': [{'id': c.id, 'name': c.name, 'email': c.email, 'phone': c.phone, 'country': c.country, 'address': c.address} for c in contacts]
    }), 200


@app.route('/user/signup', methods=['POST'])
def signup():
    
        data = request.get_json()
        error = validate_data(data)
        if error:
            return jsonify({'message': error, 'data': {}}), 400
        if User.query.filter_by(email=data['email']).first():
                        return {
                        "message": "Email already registered"
                    },400

        name = data['name']
        email = data['email']
        phone = data.get('phone')
        if phone == '':
            return {"message":"Phone cannot be blank"}, 400
        hash = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        access_token = create_access_token(identity=email)           
        add = User(name=name,email=email,phone=phone,password=hash)
        db.session.add(add)
        db.session.commit()
        return {
                "message":"User Registered Successfully",
            'data':{
                    'access_token':access_token,
                    'user':{'id':add.id, 'name':add.name, 'email':add.email}
                }
            },200
                
    
    



if __name__ == '__main__':
    app.run(debug=True, port=8000)

