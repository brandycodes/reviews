
from flask import Flask, request, redirect, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
from hashutils import make_pw_hash, check_pw_hash
from datetime import datetime


app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://spacious:6FcKKkNYfh8zgbgx@localhost:8889/spacious'
app.config['SQLALCHEMY_ECHO'] = True
app.secret_key = 'cqCUcba27gVDzMgp'
db = SQLAlchemy(app)

#Review class
class Review(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(360))
    body = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey ('user.id'))
    created = db.Column(db.DateTime)

    def __init__(self, title, body, owner, created=None):
        self.title = title
        self.body = body
        self.owner = owner
        if created is None:
            created = datetime.utcnow()
        self.created = created;

#User class
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True)
    pw_hash = db.Column(db.String(120))
    reviews = db.relationship('Review', backref='owner')

    def __init__(self, username, password):
        self.username = username
        self.pw_hash = make_pw_hash(password)


#checks that user is logged in before they can post a new review
#not a route handler, runs before every request
@app.before_request
def require_login():
    #list of routes where login isn't required, using endpoints.
    #Endpoint is the name of the *function* for that route handler,
    # not the url. For example, 'show_reviews' instead of '/review'
    allowed_routes = ['index', 'login', 'register', 'show_reviews']

    #If the user is trying to go to a restricted route(not in allowed_routes),
    #check if they are logged in. If they're not logged in, redirect them to do so.
    if request.endpoint not in allowed_routes and 'username' not in session:
        flash("Please log into your account.")
        return redirect('/login')

#Index route
@app.route('/', methods=['POST', 'GET'])
def index():
    users = User.query.all()
    return render_template('index.html', title="Spacious", users=users)

#Login route handler
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        #makes sure username/password are correct, if they are, log them in and redirect to new review
        if user and check_pw_hash(password, user.pw_hash):
            session['username'] = username
            flash('Logged in')
            return redirect('/newreview')
        #if username doesn't exist, flash error and render login
        if not user:
            flash('Username does not exist', 'error')
            return render_template('login.html')
        #if password is wrong, flash error and re-render login with username saved
        else:
            flash('Password is incorrect.', 'error')
            return render_template('login.html', username=username)

    return render_template('login.html')

#Registration route handler, creates new row in User database and redirects
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        #retrieve inputs from form
        username = request.form['username']
        password = request.form['password']
        verify = request.form['verify']
        #set up blank errors
        username_error = ''
        password_error = ''
        verify_error = ''
        space = ' '

        #make sure username doesn't already exist, pass in error if it does.
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            username_error = "Username already exists, please choose a new one."
            password = ''
            verify = ''

        #validate username
        if len(username) < 3 or len(username) > 20 or username.count(space) != 0:
            username_error = 'Please enter a valid username (3-20 characters, no spaces).'
            password = ''
            verify = ''

        #validate password
        if len(password) < 3 or len(password) >20 or password.count(space) != 0:
            password_error = "Please enter a valid password (3-20 characters, no spaces)."
            password = ''
            verify = ''
        
        #validate verify password field matches
        if verify != password:
            verify_error = "Password verification must match."
            password = ''
            verify = ''

        #if no errors, create new user and log them in
        if not username_error and not password_error and not verify_error:
            new_user = User(username,password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            flash("Account created!")
            return redirect('/newreview')
        
        #if there is an error, re-render the template with relevant error messages.
        else:
            flash("Account could not be created, see error message below.", 'error')
            return render_template('register.html', 
                title="Sign Up For An Account on Spacious!",
                username=username, username_error=username_error,
                password=password, password_error=password_error,
                verify=verify, verify_error=verify_error)
    
    return render_template('register.html')

#Logout route, deletes session and redirects user to /reviews
@app.route('/logout')
def logout():
    del session['username']
    flash("Logged out!")
    return redirect('/reviews')

#Reviews route, renders a 'list' of reviews
@app.route('/reviews', methods=['POST', 'GET'])
def show_reviews():
    
    #view a single review, url is /reviews?id=3
    if 'id' in request.args:
        review_id = request.args.get('id')
        reviews = Review.query.filter_by(id=review_id)
        return render_template('single_review.html', reviews=reviews)
    
    #view all reviews for one user, url is /reviews?user=brandy
    elif 'user' in request.args:
        author = request.args.get('user')
        user = User.query.filter_by(username=author).first()
        reviews = user.reviews
        return render_template('single_user.html', author=author, user=user, reviews=reviews)

    #view all reviews by all users, url is just /reviews
    else:
        reviews = Review.query.all()
        return render_template('reviews.html', title="Spacious Reviews -- Will You Fit In?", reviews=reviews)

#New review route, allows user to post a new review     
@app.route('/newreview', methods=['POST', 'GET'])
def create_new_review():
    #Renders blank review form
    if request.method == 'GET':
        return render_template('new_review.html', title="Spacious -- Create a New Review")
    
    #Validates new review and sends to Review database
    if request.method == 'POST':
        #Retrieve the logged-in user's username
        user = User.query.filter_by(username=session['username']).first()
        #Retrieve review content from the form
        review_title = request.form['title']
        review_body = request.form['body']
        new_review = Review(review_title, review_body, user)
        #set errors blank before they're checked
        title_error = ''
        body_error = ''

        #Check errors/generate error messages
        if len(review_title) == 0:
            title_error = "Please enter a title for your review."
        if len(review_body) == 0:
            body_error = "Please enter text for your review."

        #if everything is in order, add new review to Reviews table and redirect to the new post
        if not title_error and not body_error:
            #new_review = Review(review_title, review_body, user)
            db.session.add(new_review)
            db.session.commit()
            return redirect('/reviews?id={}'.format(new_review.id))
        
        #if something's wrong, render template with errors shown
        else:
            return render_template('new_review.html', title="Spacious -- Write a New Review", reviews=reviews,
                review_title=review_title, title_error=title_error, 
                review_body=review_body, body_error=body_error)

if __name__ == '__main__':
    app.run()
    