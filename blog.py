import hashlib
import hmac
import os
import random
import re
from string import letters

import jinja2
import webapp2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'ghjjaytevkhefbm'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

""" This class contains all the methods for the session variables. """


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


''' User DB Model '''


class User(db.Model):

    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


""" blog stuff """


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


""" Comment model """


class Comment(db.Model):
    user_name = db.StringProperty(required=True)
    comment = db.StringProperty(required=False)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


""" Like Model """


class Like(db.Model):
    user = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)


"""" Post model """


class Post(db.Model):
    user = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    numOfLikes = db.IntegerProperty(required=True)

    def render(self):
        """
        This method is called whenever front.html is rendered.
        """
        self._render_text = self.content.replace('\n', '<br>')
        self.render_comment = Comment.gql("where post_id=" +
                                          str(self.key().id()))
        return render_str("post.html", p=self)


# Handler for /blog


class BlogFront(BlogHandler):
    """ This get method is called when /blog is hit. """
    def get(self):
        if not self.user:
            return self.redirect('/login')
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)

    def post(self):
        """ This post method defines the functionality for Edit_Post,
         Delete_Post, Comment, Edit_Comment, Delete_Comment,
          Like and UnLike Buttons on /blog page. """
        if not self.user:
            return self.redirect('/login')

        if self.request.get('Comment'):
            comment = self.request.get('comment')
            if comment:
                c = Comment(parent=blog_key(), user_name=self.user.name,
                            post_id=long(self.request.get('post_id')),
                            comment=comment)
                c.put()
                return self.redirect('/blog')
            else:
                error = "Enter comment, please!"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)

        if self.request.get('Like'):
            post_id = self.request.get('post_id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            users = db.GqlQuery("select user from Like where post_id=" +
                                str(post.key().id()))
            if not self.user.key().id() == post.user:
                user_exists = False
                for u in users:
                    if self.user.key().id() == int(u.user):
                        user_exists = True
                        break
                if not user_exists:
                    post.numOfLikes += 1
                    db.put(post)
                    l = Like(parent=blog_key(), user=self.user.key().id(),
                             post_id=int(post_id))
                    l.put()
                return self.redirect('/blog')
            else:
                error = "user does not have permission to like his own post"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)

        if self.request.get('Unlike'):
            post_id = self.request.get('post_id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            users = db.GqlQuery("select user from Like where post_id=" +
                                str(post.key().id()))
            if not self.user.key().id() == post.user:
                for u in users:
                    if self.user.key().id() == int(u.user):
                        post.numOfLikes -= 1
                        db.put(post)
                        current_user = db.GqlQuery("select * from Like"
                                                   " where user=" +
                                                   str(self.user.key().id()))
                        db.delete(current_user)
                return self.redirect('/blog')
            else:
                error = "user does not have permission to unlike his own post"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)


class EditComment(BlogHandler):

    def get(self, comment_id):
        """ This get method is called when /blog/editcomment/%s is hit.
         It renders the edit-comment.html page. """
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        if comment:
            if not self.user:
                return self.redirect('/login')
            if self.user.name == comment.user_name:
                self.render("edit-comment.html", new_comment=comment)
            else:
                error = "user does not have permission to edit this comment"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)
        else:
            error = "comment does not exist"
            posts = Post.all().order('-created')
            self.render("front.html", posts=posts, error=error)

    def post(self, c_id):
        """ This post method is called when Update_Comment button is hit.
         It updates the Comment DB with the new comment. """
        key = db.Key.from_path('Comment', int(c_id), parent=blog_key())
        comment = db.get(key)
        if comment:
            if not self.user:
                return self.redirect('/login')
            if self.user.name == comment.user_name:
                if self.request.get('Update_Comment'):
                    edited_comment = self.request.get('new_comment')
                    if edited_comment:
                        comment.comment = edited_comment
                        comment.put()
                        return self.redirect('/blog')
                    else:
                        error = "Enter comment, please!"
                        posts = Post.all().order('-created')
                        self.render("front.html", posts=posts, error=error)
            else:
                error = "user does not have permission to edit this comment"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)
        else:
            error = "comment does not exist"
            posts = Post.all().order('-created')
            self.render("front.html", posts=posts, error=error)


class DeleteComment(BlogHandler):

    def get(self, comment_id):
        """ This get method is called when /blog/deletecomment/%s is hit.
          """
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        if comment:
            if not self.user:
                return self.redirect('/login')
            if self.user.name == comment.user_name:
                comment.delete()
                return self.redirect('/blog')
            else:
                error = "user does not have permission to delete this comment"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)
        else:
            error = "comment does not exist"
            posts = Post.all().order('-created')
            self.render("front.html", posts=posts, error=error)

""" Handler for permalink """


class PostPage(BlogHandler):
    def get(self, post_id):
        """ This get method is called after a new post is created or
         when a user wants to edit a post."""
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

    def post(self, post_id):
        """ This post method is called when a user wants to perform
         Edit_Post, Edit_Comment, Delete_Post, Delete_Comment, Like,
          Unlike from Permalink page."""
        if not self.user:
            return self.redirect('/login')

        if self.request.get('Comment'):
            comment = self.request.get('comment')
            if comment:
                c = Comment(parent=blog_key(), user_name=self.user.name,
                            post_id=long(self.request.get('post_id')),
                            comment=comment)
                c.put()
                return self.redirect('/blog')
            else:
                error = "Enter comment, please!"
                posts = Post.all().order('-created')
                self.render("post.html", posts=posts, error=error)

        if self.request.get('Like'):
            post_id = self.request.get('post_id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            users = db.GqlQuery("select user from Like where post_id=" +
                                str(post.key().id()))
            if not self.user.key().id() == post.user:
                user_exists = False
                for u in users:
                    if self.user.key().id() == int(u.user):
                        user_exists = True
                        break
                if not user_exists:
                    post.numOfLikes += 1
                    db.put(post)
                    l = Like(parent=blog_key(), user=self.user.key().id(),
                             post_id=int(post_id))
                    l.put()
                self.redirect('/blog')
            else:
                error = "user does not have permission to like his own post"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)

        if self.request.get('Unlike'):
            post_id = self.request.get('post_id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            users = db.GqlQuery("select user from Like where"
                                " post_id=" + str(post.key().id()))
            if not self.user.key().id() == post.user:
                for u in users:
                    if self.user.key().id() == int(u.user):
                        post.numOfLikes -= 1
                        db.put(post)
                        current_user = db.GqlQuery("select * from Like"
                                                   " where user=" +
                                                   str(self.user.key().id()))
                        db.delete(current_user)
                        break
                return self.redirect('/blog')
            else:
                error = "user does not have permission to unlike his own post"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)


# Handler for editing a post
class EditPost(BlogHandler):
    def get(self, post_id):
        """ This get method is called when /blog/editpost/%s is hit.
                 It renders the newpost.html page. """
        if not self.user:
            self.redirect('/login')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            if self.user.key().id() == post.user:
                self.render("newpost.html", subject=post.subject,
                            content=post.content)
            else:
                error = "user does not have permission to edit this post"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)
        else:
            error = "post does not exist"
            posts = Post.all().order('-created')
            self.render("front.html", posts=posts, error=error)

    def post(self, post_id):
        """ This post method is called when Update_Post button is hit.
                It updates the Post DB with the new post. """
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            subject = self.request.get('subject')
            content = self.request.get('content')
            if self.user.key().id() == post.user:
                if subject and content:
                    key = db.Key.from_path('Post', int(post_id),
                                           parent=blog_key())
                    post = db.get(key)
                    post.subject = subject
                    post.content = content
                    post.put()
                    return self.redirect('/blog')
                else:
                    error = "subject and content, please!"
                    self.render("newpost.html", subject=subject,
                                content=content,
                                error=error)
            else:
                error = "user does not have permission to edit this post"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)
        else:
            error = "post does not exist"
            posts = Post.all().order('-created')
            self.render("front.html", posts=posts, error=error)


class DeletePost(BlogHandler):
    def get(self, post_id):
        """ This get method is called when /blog/deletepost/%s is hit. """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            if not self.user:
                self.redirect('/login')
            if self.user.key().id() == post.user:
                post.delete()
                return self.redirect('/blog')
            else:
                error = "user does not have permission to delete this post"
                posts = Post.all().order('-created')
                self.render("front.html", posts=posts, error=error)
        else:
            error = "post does not exist"
            posts = Post.all().order('-created')
            self.render("front.html", posts=posts, error=error)


class NewPost(BlogHandler):
    def get(self):
        """ This get method is called when a user wants
         to create a new post. """
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        """ This post method is called when a user enters the
         post fields and hits Submit. """
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), user=self.user.key().id(),
                     subject=subject, content=content, numOfLikes=0)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content,
                        error=error)

        if self.request.get('Cancel'):
            return self.redirect('/blog')


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        """ This get method displays the SignUp form. """
        self.render("signup-form.html")

    def post(self):
        """ This post method takes in SignUp fields and verifies them. """
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        """ This method checks if user already exists. If not,
         it enters the user in the DB. """
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/login')


class Login(BlogHandler):
    """ This method is called when Login is clicked. """
    def get(self):
        self.render('login-form.html')

    def post(self):
        """This post method takes in Login arguments and
         checks against DB and displays welcome page. """
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    """ This method ends the session of a user and
    redirects to SignUp page."""
    def get(self):
        self.logout()
        self.redirect('/login')


class Unit3Welcome(BlogHandler):
    """ This method is called when a user logs in and
    displays the welcome page. """
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', Register),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Unit3Welcome),
                               ],
                              debug=True)
