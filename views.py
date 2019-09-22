from database_setup import Base, User, Catalog, Item
from flask import Flask, jsonify, request, url_for, abort, g
from flask import render_template, redirect, flash
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from flask_httpauth import HTTPBasicAuth
from flask import session as login_session
from flask import make_response
from google.oauth2 import id_token
from google.auth.transport import requests as googlerequests
import random
import string
import json
import httplib2
import requests

auth = HTTPBasicAuth()


engine = create_engine('postgresql://catalog:catalog@localhost:5432/catalogwithusers',
    pool_size=20, max_overflow=0)

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'

CLIENT_ID = json.loads(
    open('/var/www/CatalogApp/CatalogApp/client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalog app"


# create a state token to prevent request forgery
# store it in the session for later validation
@app.route("/login")
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    content = request.get_json()
    # Obtain authorization code
    code = content['id']
    try:
        # Upgrade the authorization code into a credentials object
        idinfo = id_token.verify_oauth2_token(code, googlerequests.Request(),
                                              CLIENT_ID)
        if idinfo['iss'] not in ['accounts.google.com',
                                 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
    except:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = content['access']
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = idinfo['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
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
        response = make_response(json.dumps('Current user is connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if the user available in the database
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:'
    output += '150px;-webkit-border-radius:150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/gcdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if not access_token:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # make API call to google oauth2 to revoke access token
    url = 'https://accounts.google.com/o/oauth2/revoke?token='
    url += login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # if API call to google is successful, remove user login session info
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # raise error if API call is not successful
    else:
        response = make_response(json.dumps('Failed to revoke token.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# ADD @auth.verify_password here
@auth.verify_password
def verify_password(username, password):
    session = DBSession()
    user = session.query(User).filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True


# ADD a /users route here
@app.route("/users", methods=['POST'])
def addUser():
    session = DBSession()
    username = request.json.get("username")
    password = request.json.get("password")
    # check if either username or password is empty
    if username is None or password is None:
        abort(400)
    # check if user already exist
    if session.query(User).filter_by(username=username).first():
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({'username': user.username}), 201


@app.route('/')
def showCatalogsAndItems():
    if request.method == 'GET':
        catalogs = getAllCatalogs()
        items = getAllItems()
        loggedIn = False
        if 'username' in login_session:
            loggedIn = True
        return render_template('catalogs.html', catalogs=catalogs,
                               items=items, loggedIn=loggedIn)


@app.route('/catalog/<cat_name>/items')
def showCatalogInfo(cat_name):
    if request.method == 'GET':
        catalogs = getAllCatalogs()
        cat_id = getCatalogInfoByName(cat_name).get('id')
        items = getItemsInCatalog(cat_id)
        loggedIn = False
        if 'username' in login_session:
            loggedIn = True
        return render_template('showCatalog.html',
                               count=len(items),
                               catalogs=catalogs,
                               items=items,
                               loggedIn=loggedIn)


@app.route('/catalog/<cat_name>/<item_name>')
def showItemInfo(cat_name, item_name):
    loggedIn = False
    if 'username' in login_session:
        loggedIn = True
    if request.method == 'GET':
        item_info = getItemInfoByName(item_name)
        if item_info:
            user_id = item_info.get('user_id')
            isowner = False
            if login_session.get('user_id') == user_id:
                isowner = True
            return render_template('showItem.html',
                                   item=item_info,
                                   loggedIn=loggedIn,
                                   isowner=isowner)
        # handle cases where an item is not found
        else:
            error = item_name + ' is not in the database'
            return render_template('error.html', error=error,
                                   loggedIn=loggedIn)


@app.route('/catalog/<cat_name>/<item_name>/JSON')
def showiteminfoasjson(cat_name, item_name):
    if request.method == 'GET':
        # retrieve all catalogs along with the info
        item_info = getItemInfoByName(item_name)
        if item_info:
            return jsonify(item_info)
        else:
            return jsonify({'error': "item not found!"})
    else:
        return jsonify({"error": "Invalid HTTP method"}), 405


@app.route('/catalog/add', methods=['GET', 'POST'])
def addItem():
    if 'username' not in login_session:
        return redirect('/login')
    user_id = login_session['user_id']
    if request.method == 'GET':
        catalogs = getAllCatalogs()
        return render_template('addItem.html',
                               catalogs=catalogs,
                               loggedIn=True)
    elif request.method == 'POST':
        title = request.form.get('title')
        if not title:
            return render_template('error.html',
                                   error="Please provide for the item",
                                   loggedIn=True)
        description = request.form.get('description')
        catalog = request.form.get('catalog')
        item = addItemInfo(user_id, title, description, catalog)
        if item:
            return redirect(url_for('showCatalogsAndItems', loggedIn=True))
        else:
            return render_template('error.html',
                                   error="add item not succesful",
                                   loggedIn=True)


@app.route('/catalog/<item_name>/edit', methods=['GET', 'POST'])
def editItemInfo(item_name):
    # if not logged in, return to login page
    if 'username' not in login_session:
        return redirect('/login')
    item_info = getItemInfoByName(item_name)
    # check if item exists
    if not item_info:
        error = item_name + ' is not in the database'
        return render_template('error.html', error=error)
    # check if user_id for item match session's current user_id
    catalogs = getAllCatalogs()
    user_id = item_info.get('user_id')
    if login_session.get('user_id') != user_id:
        return render_template('editItem.html',
                               catalogs=catalogs,
                               item=item_info,
                               loggedIn=True,
                               isowner=False)
    if request.method == 'GET':
        return render_template('editItem.html',
                               catalogs=catalogs,
                               item=item_info,
                               loggedIn=True,
                               isowner=True)
    elif request.method == 'POST':
        title = request.form.get('title')
        if not title:
            return render_template('error.html',
                                   error="Please provide title for the item",
                                   loggedIn=True)
        description = request.form.get('description')
        catalog = request.form.get('catalog')
        item = editItem(item_info.get('id'), title, description, catalog)
        if item:
            return redirect(url_for('showCatalogsAndItems', loggedIn=True))
        else:
            return render_template('error.html',
                                   error='edit not succesful, try again!',
                                   loggedIn=True)


@app.route('/catalog/<item_name>/delete', methods=['GET', 'POST'])
def deleteItemInfo(item_name):
    if 'username' not in login_session:
        return redirect('/login')
    item_info = getItemInfoByName(item_name)
    # check if item exists
    if not item_info:
        error = item_name + ' is not in the database'
        return render_template('error.html', error=error)
    # check if user_id for item match session's current user_id
    user_id = item_info.get('user_id')
    if login_session.get('user_id') != user_id:
        return render_template('deleteItem.html',
                               item=item_info,
                               loggedIn=True,
                               isowner=False)
    if request.method == 'GET':
        return render_template('deleteItem.html',
                               item=item_info,
                               loggedIn=True,
                               isowner=True)
    elif request.method == 'POST':
        delete = deleteItem(item_info['id'])
        if delete == 'item deleted':
            return redirect(url_for('showCatalogsAndItems',
                                    loggedIn=True))
        else:
            return render_template('error.html',
                                   error='delete not succesful, try again!')


@app.route('/catalog.json')
def listCatalogsAndItems():
    if request.method == 'GET':
        # retrieve all catalogs along with the info
        catalogs = getAllCatalogs()
        results = {'Category': []}
        for catalog in catalogs:
            cat_id = catalog['id']
            # retrieve items info from the catalog
            items = getItemsInCatalog(cat_id)
            if items:
                catalog['Item'] = items
            results['Category'].append(catalog)
        return jsonify(results)
    else:
        return jsonify({"error": "Invalid HTTP method"}), 405


def createUser(login_session):
    session = DBSession()
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    session = DBSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getAllCatalogs():
    """Get all categories in db in serialized format"""
    session = DBSession()
    catalogs = session.query(Catalog).all()
    return [catalog.serialize for catalog in catalogs]


def getCatalogNameByID(cat_id):
    session = DBSession()
    cat_name = session.query(Catalog).filter_by(id=cat_id).first().serialize
    cat_name = cat_name.get('name')
    return cat_name


def getAllItems():
    """Get all items stored in the database along with item info"""
    session = DBSession()
    items = session.query(Item).all()
    result = []
    for item in items:
        item = item.serialize
        item['cat_name'] = getCatalogNameByID(item.get('cat_id'))
        result.append(item)
    return result


def getCatalogInfoByName(cat_name):
    """Get info about Catalog"""
    session = DBSession()
    item = session.query(Catalog).filter_by(name=cat_name).first()
    if item:
        return item.serialize
    else:
        return


def getItemsInCatalog(cat_id):
    """Get info about items belonging to a specific catalog"""
    session = DBSession()
    cat_name = getCatalogNameByID(cat_id)
    items = session.query(Item).filter_by(cat_id=cat_id)
    result = []
    for item in items:
        item = item.serialize
        item['cat_name'] = cat_name
        result.append(item)
    return result


def getItemInfo(item_id):
    """Get info about an item based on item id stored in db"""
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).first()
    if item:
        return item.serialize
    else:
        return


def getItemInfoByName(item_name):
    """Get info about an item based on item id stored in db"""
    session = DBSession()
    item = session.query(Item).filter_by(title=item_name).first()
    if item:
        return item.serialize
    else:
        return


def addItemInfo(user_id, title=None, description=None, category=None):
    """Add an item based on user provided title/descriptin/category info"""
    session = DBSession()
    cat_id = getCatalogInfoByName(category).get('id')
    item = Item(user_id=user_id, title=title,
                description=description, cat_id=cat_id)
    session.add(item)
    session.commit()
    return item.serialize


def editItem(item_id, title=None, description=None, category=None):
    """Edit an item based on user provided title/descriptin/category info"""
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    if title:
        item.title = title
    if description:
        item.description = description
    if category:
        item.cat_id = getCatalogInfoByName(category).get('id')
    session.add(item)
    session.commit()
    return item.serialize


def deleteItem(item_id):
    """Delete an item in database by item id"""
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    session.delete(item)
    session.commit()
    return "item deleted"


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
