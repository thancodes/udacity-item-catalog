"""
    Udacity Nanodegree Catalog
    The course catalog example app written with Flask, and sqlite3
"""
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Course

from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response, jsonify
import httplib2
import json
import requests

app = Flask(__name__)

engine = create_engine('sqlite:///item-catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Google+ client id and application name
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Udacity Nanodegree Catalog"


def createUser(login_session):
    u = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(u)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def user_allowed_to_browse():
    return 'email' in login_session


def user_allowed_to_edit(m):
    return ('user_id' in login_session and
            m.user_id == login_session['user_id'])


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' in login_session:
            return f(*args, **kwargs)
        else:
            flash('You are not allowed to access there', 'danger')
            return redirect('/login')

    return decorated_function


@app.context_processor
def inject_user_logged_in():
    return dict(user_logged_in=user_allowed_to_browse())


@app.route('/login')
def showLogin():
    """
    Open login page contains google signin button
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Connect google account.
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
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
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
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
    output += """
        " style = "width: 80px; height: 80px;border-radius: 50%;
         -webkit-border-radius: 50%;-moz-border-radius: 50%;"> '
         """
    flash("Welcome, you are now logged in as %s." % login_session['username'], 'success')
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """
    Log out from google.
    """
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
def index():
    """
    List all of the categories, and latest course
    """
    categories = session.query(Category).all()
    latest_courses = session.query(Course).order_by(Course.id.desc()).all()
    return render_template('home.html',
                           categories=categories,
                           courses=latest_courses)


@app.route('/catalog/<int:category_id>')
@app.route('/category/<int:category_id>')
def view_category(category_id):
    """
    Show details of selected category
    """
    categories = session.query(Category).all()
    try:
        category = session.query(Category).filter_by(id=category_id).one()
    except:
        flash('Sorry, something went wrong.', 'danger')
        return redirect(url_for('index'))

    category_courses = session.query(Course).filter_by(category_id=category.id)
    return render_template('view_category.html',
                           categories=categories,
                           category=category,
                           courses=category_courses)


@app.route('/course/<int:course_id>')
def view_course(course_id):
    """
    Show details of selected course
    """
    try:
        course = session.query(Course).filter_by(id=course_id).one()
    except:
        flash('Sorry, something went wrong.', 'danger')
        return redirect(url_for('index'))

    return render_template('view_course.html',
                           course=course)


@app.route('/course/new', methods=['GET', 'POST'])
@login_required
def new_course():
    """
    Allow logged users to create a course
    """
    # # check user logged in
    # if not user_allowed_to_browse():
    #     flash('You need to login!', 'danger')
    #     return redirect(url_for('showLogin'))

    if request.method == 'POST':
        thumbnail_url = str(request.form['thumbnail_url'])
        if thumbnail_url == "":
            thumbnail_url = "https://placehold.it/300x200"

        course = Course(name=request.form['name'],
                        description=request.form['description'],
                        number=request.form['number'],
                        url=request.form['url'],
                        thumbnail_url=thumbnail_url,
                        category_id=request.form['category_id'],
                        user=getUserInfo(login_session['user_id']))
        session.add(course)
        try:
            session.commit()
            flash('New course created!', 'success')
            return redirect(url_for('view_course', course_id=course.id))
        except Exception as e:
            flash('Something went wrong. {}'.format(e), 'danger')
            return redirect(url_for('index'))
    else:
        categories = session.query(Category).all()
        course = {
            'id': None,
            'name': "",
            'description': "",
            'number': "",
            'url': "",
            'thumbnail_url': "",
            'category_id': None,
        }

        return render_template('edit_course.html',
                               categories=categories,
                               course=course,
                               form_action=url_for('new_course'))


@app.route('/course/<int:course_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_course(course_id):
    """
    Allow logged users to edit a course
    """
    # # check user logged in
    # if not user_allowed_to_browse():
    #     flash('You need to login!', 'danger')
    #     return redirect(url_for('showLogin'))

    course = session.query(Course).filter_by(id=course_id).one()

    # check user is owner of the item
    if not user_allowed_to_edit(course):
        flash(
            'You are not authorized to edit this course, '
            'but you can always create yours and then edit them if you want.',
            'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        thumbnail_url = str(request.form['thumbnail_url'])
        if thumbnail_url == "":
            thumbnail_url = "https://placehold.it/300x200"

        course.name = request.form['name']
        course.description = request.form['description']
        course.number = request.form['number']
        course.url = request.form['url']
        course.thumbnail_url = thumbnail_url
        course.category_id = request.form['category_id']
        session.add(course)
        try:
            session.commit()
            flash('Update Course `%s` Successfully.' % course.name, 'success')
        except Exception as e:
            flash('Update Course `%s` Unsuccessfully. %s' % (course.name, e), 'danger')

        return redirect(url_for('view_course', course_id=course.id))
    else:
        categories = session.query(Category).all()

        return render_template('edit_course.html',
                               categories=categories,
                               course=course)


@app.route('/courses/<int:course_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_course(course_id):
    """
    Allow logged users to add a delete
    """
    # # check user logged in
    # if not user_allowed_to_browse():
    #     flash('You need to login!', 'danger')
    #     return redirect(url_for('showLogin'))

    course = session.query(Course).filter_by(id=course_id).one()

    # check user is owner of the item
    if not user_allowed_to_edit(course):
        flash(
            'You are not authorized to edit this course, '
            'but you can always create yours and then delete them if you want.',
            'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        category = session.query(Category).filter_by(id=course.category_id).one()
        session.delete(course)
        try:
            session.commit()
            flash('Delete Course `%s` Successfully.' % course.name, 'success')
            return redirect(url_for('view_category', category_id=category.id))
        except Exception as e:
            flash('Something went wrong. {}'.format(e), 'danger')
            return redirect(url_for('view_course', course_id=course.id))
    else:
        return render_template('delete_course.html', course=course)


@app.route('/catalog.json')
@app.route('/categories.json')
def api_categories():
    """
    API JSON Format: List all of the categories
    """
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/catalog/<int:category_id>/JSON')
@app.route('/category/<int:category_id>/JSON')
def api_view_category(category_id):
    """
    API JSON Format: Show details of selected category
    """
    category = session.query(Category).filter_by(id=category_id).one()
    return jsonify(category.serialize)


@app.route('/courses.json')
def api_courses():
    """
    API JSON Format: List all of the courses
    """
    courses = session.query(Course).all()
    return jsonify(courses=[c.serialize for c in courses])


@app.route('/course/<int:course_id>/JSON')
def api_view_course(course_id):
    """
    API JSON Format: Show details of selected course
    """
    course = session.query(Course).filter_by(id=course_id).one()
    return jsonify(course.serialize)


if __name__ == '__main__':
    app.secret_key = 'secret'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
