Catalog App Project

## Requirements and dependencies
Start your virtual environemnt and go to the "Catalog" folder, run `pip install -r requirements.txt`.

Required python packages
1. SQLAlchemy
2. requests
3. oauth2client
4. flask
5. google-oauth2-tool
6. Flask-HTTPAuth

## Initialize

1. Initialize the database
`python lotsofitems.py`

2. Start the server
`python views.py`

## Features

### 1. API Endpoint
url: http://localhost:5000/catalog.json

### 2. SignIn
url: http://localhost:5000/login
SignIn is implemented through google Authentication.
*Note*: If sign in is successful, but it doesn't redirect you to the front page. You might need to refresh the page.

### 3. View all items in the store
url: http://localhost:5000

### 4. View items from a specific catalog
url: http://localhost:5000/catalog/<catalog_name>/items

### 5. View a specific item
url: http://localhost:5000/catalog/<catalog_name>/<item_name>

### 6. View a specific item in JSON format
url: http://localhost:5000/catalog/<catalog_name>/<item_name>/JSON

### 7. Add an item
url: http://localhost:5000/catalog/add
This can only be available when user has signed in.

### 8. Delete an item
Implemented.
url: http://localhost:5000/catalog/<item_name>/delete
This is only available when user has signed in and the item is created by the user.

### 9. Edit/Update an item
Implemented.
url: http://localhost:5000/catalog/<item_name>/edit
This is only available when user has signed in and the item is created by the user.
