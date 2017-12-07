import json
import random
import string

import httplib2
import requests
from flask import Flask, request, flash, render_template, url_for, redirect, \
    jsonify, g, abort
from flask import make_response
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, Item, User

auth = HTTPBasicAuth()

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.debug = True

engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Set global variable for sending http requests
h = httplib2.Http(disable_ssl_certificate_validation=True)


# Create anti-forgery state token
@app.route('/login/')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/')
@app.route('/category/')
def show_all_categories():
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('publiccategories.html', categories=categories)
    else:
        return render_template('categories.html', categories=categories)


@app.route('/category/new/', methods=['GET', 'POST'])
def add_new_category():
    if 'username' not in login_session:
        return redirect('/login')
    else:
        if request.method == 'POST':
            new_category = Category(name=request.form['name'],
                                    user_id=login_session['user_id'])
            session.add(new_category)
            session.commit()
            flash("New category created!")
            return redirect(url_for('show_all_categories'))
        else:
            return render_template('addcategory.html')


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def edit_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    else:
        edited_category = session.query(Category).filter_by(id=category_id) \
            .one()
        if edited_category.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are " \
                   "not authorized to edit this category." \
                   " Please create your own category in order to edit.');}" \
                   "</script><body onload='myFunction()'>"
        if request.method == 'POST':
            if request.form['name']:
                edited_category.name = request.form['name']
                session.add(edited_category)
                session.commit()
                flash("Category edited!")
                return redirect(url_for('show_all_categories'))
        else:
            return render_template('editcategory.html',
                                   category_id=category_id,
                                   category=edited_category)


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def delete_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    else:
        deleted_category = session.query(Category).filter_by(
            id=category_id).one()
        if deleted_category.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are " \
                   "not authorized to delete this category." \
                   " Please create your own category in order to delete.');}" \
                   "</script><body onload='myFunction()'>"
        if request.method == 'POST':
            session.delete(deleted_category)
            session.commit()
            flash("Category deleted successfully!")
            return redirect(url_for('show_all_categories'))
        else:
            return render_template('deletecategory.html',
                                   category_id=category_id,
                                   category=deleted_category)


@app.route('/category/<int:category_id>/items/')
def show_all_category_items(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    creator = get_user_info(category.user_id)
    items = session.query(Item).filter_by(category_id=category_id)
    if 'username' not in login_session or creator.id != \
            login_session['user_id']:
        return render_template('publicitems.html', category=category,
                               items=items)
    else:
        return render_template('items.html', category=category, items=items)


@app.route('/category/<int:category_id>/items/<int:item_id>/')
def show_category_item(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return render_template('publicitemdetails.html', category=category,
                               item=item)
    else:
        return render_template('itemdetails.html', category=category,
                               item=item)


@app.route('/category/<int:category_id>/items/new/', methods=['GET', 'POST'])
def add_new_category_item(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    else:
        category = session.query(Category).filter_by(id=category_id).one()
        if request.method == 'POST':
            new_item = Item(name=request.form['name'],
                            description=request.form['description'],
                            category_id=category_id,
                            user_id=login_session['user_id'])
            session.add(new_item)
            session.commit()
            flash("New category item created!")
            return redirect(url_for('show_all_categories'))
        else:
            return render_template('addcategoryitem.html', category=category)


@app.route('/category/<int:category_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def edit_category_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    else:
        category = session.query(Category).filter_by(id=category_id).one()
        edited_item = session.query(Item).filter_by(id=item_id).one()
        if edited_item.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are " \
                   "not authorized to edit this category item." \
                   " Please create your own item in order to edit.');}" \
                   "</script><body onload='myFunction()'>"
        if request.method == 'POST':
            if request.form['name']:
                edited_item.name = request.form['name']
                edited_item.description = request.form['description']
                session.add(edited_item)
                session.commit()
                flash("category item edited!")
                return redirect(url_for('show_all_categories'))
        else:
            return render_template('editcategoryitem.html', category=category,
                                   item=edited_item)


@app.route('/category/<int:category_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def delete_category_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    else:
        category = session.query(Category).filter_by(id=category_id).one()
        deleted_item = session.query(Item).filter_by(id=item_id).one()
        if deleted_item.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are " \
                   "not authorized to delete this category item." \
                   " Please create your own item in order to delete.');}" \
                   "</script><body onload='myFunction()'>"
        if request.method == 'POST':
            session.delete(deleted_item)
            session.commit()
            flash("category item deleted!")
            return redirect(url_for('show_all_categories'))
        else:
            return render_template('deletecategoryitem.html',
                                   category=category,
                                   item=deleted_item)


# User Helper Functions
def create_user(login_session):
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."),
            401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    login_session['provider'] = 'google'
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;' \
              'border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """
    Revoke a current user's token and reset their login_session
    :return:
    """
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        login_session['username'] = login_session['username']
        login_session['email'] = login_session['email']
        login_session['picture'] = login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('show_all_categories'))
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """
    Connect the user using their facebook account
    :return:
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?' \
          'grant_type=fb_exchange_token&client_id=%s&client_secret=%s&' \
          'fb_exchange_token=%s' % (
              app_id, app_secret, access_token)
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/' \
          'me?access_token=%s&fields=name,id,email' % token
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token' \
          '=%s&redirect=0&height=200&width=200' % token
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;' \
              'border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """
    Revoke a current user's token and reset their login_session
    :return:
    """
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    result = h.request(url, 'DELETE')[1]
    return redirect(url_for('show_all_categories'))


@app.route('/disconnect')
def disconnect():
    """
    Disconnecting the user based on the provider
    :return:
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('show_all_categories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_all_categories'))


@auth.verify_password
def verify_password(email, password):
    user = session.query(User).filter_by(email=email).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True


@app.route('/categories/JSON')
def categories_json():
    """
    Making an API Endpoint for a GET categories request
    :return: categories
    """
    categories = session.query(Category).all()
    return jsonify(Categories=[category.serialize for category in categories])


@app.route('/categories/<int:category_id>/JSON')
def category_json(category_id):
    """
    Making an API Endpoint for a GET a specific category request
    :return: categories
    """
    category = session.query(Category).filter_by(id=category_id).one()
    return jsonify(Category=category.serialize)


@app.route('/categories/<int:category_id>/items/JSON')
def category_items_json(category_id):
    """
    Making an API Endpoint for a GET category items request
    :param category_id:
    :return: category items
    """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category.id)
    return jsonify(CategoryItems=[item.serialize for item in items])


@app.route('/categories/<int:category_id>/items/<int:item_id>/JSON')
def category_item_json(category_id, item_id):
    """
    Making an API Endpoint for a GET a specific category item request
    :param category_id:
    :param item_id:
    :return: category item
    """
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(category_id=category.id,
                                         id=item_id).one()
    return jsonify(CategoryItem=item.serialize)


@app.route('/users/JSON')
def users_json():
    """
    Making an API Endpoint for a GET users request
    :return:
    """
    users = session.query(User).all()
    return jsonify(Users=[user.serialize for user in users])


@app.route('/users/<int:user_id>/JSON')
def user_json(user_id):
    """
    Making an API Endpoint for a GET a specific user request
    :return:
    """
    user = session.query(User).filter_by(id=user_id)
    return jsonify(User=user.serialize)


@app.route('/users', methods=['POST'])
def new_user():
    """
    Creating a user using an API call
    :return: a new user if the user does not already exist
    """
    email = request.json.get('email')
    password = request.json.get('password')
    name = request.json.get("name")
    picture = request.json.get("picture")
    if email is None or password is None or name is None or picture is None:
        print("missing arguments")
        abort(400)
    if session.query(User).filter_by(email=email).first() is not None:
        print("existing user")
        user = session.query(User).filter_by(email=email).first()
        return jsonify({'message': 'user already exists',
                        'User': user.serialize}), 200
    user = User(email=email, name=name, picture=picture)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify(User=user.serialize), 201


@app.route('/resource')
@auth.login_required
def get_user():
    """
    Getting user data after creating user through API call
    :return: json object that say's Hello to the user
    """
    return jsonify({'data': 'Hello, %s!' % g.user.name})


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
