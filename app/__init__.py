from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import json
import utils
from flask import request, redirect, session,render_template, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
    current_user
import requests
app = Flask(__name__)
from app import views
#bcrypt for storing passwords.
from bcrypt import hashpw, gensalt
import yaml
#for logging
import raven

#for memcache
import memcache


import os


filepath = os.getcwd() + '/config/application.yml'
print filepath
with open(filepath, 'r') as stream:
    try:
        yaml_config = yaml.load(stream)
    except yaml.YAMLError as exc:
        print(exc)

app.config['WTF_SCRF_ENABLED'] = True
app.config['SECRET_KEY'] = yaml_config['SECRET_KEY']

mysql_username = yaml_config['mysql_username']
mysql_password = yaml_config['mysql_password']
mysql_host  =yaml_config['mysql_host']
mysql_db = yaml_config['mysql_db']
sentry_url = yaml_config['sentry_url']
memcache_host = yaml_config['memcache_host']
memcache_port = yaml_config['memcache_port']

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://' + mysql_username + ':' + mysql_password + '@' + mysql_host + '/' + mysql_db
db = SQLAlchemy(app)
lm = LoginManager(app)
lm.login_view = '/admin/login'

sentry = raven.Client(sentry_url)
client = memcache.Client([(memcache_host, memcache_port)])


class CompanyAdmin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=False, nullable=False)
    apitoken = db.Column(db.String(120), unique=False, nullable=True)
    company_id = db.Column(db.Integer,unique=False, nullable=False)

def fetch_from_cache(url):	
	mydict =  client.get(url)
	if not mydict:
		#get fresh
		cobj = CompanyAdmin.query.filter_by(username=session['username']).first()			
		token = "Bearer " + cobj.apitoken			
		headers = {'authorization': token}
		response = requests.request("GET", url, headers=headers)
		ret = response.text		
		mydict = json.loads(ret)
		#save to cache
		client.set(url,mydict)
		return mydict
	else:
		return mydict
 
@app.route("/admin/logout")
def admin_logout():
	#app.logger.info("logout requested for user")
	#sentry.captureMessage("logout requested for user")
	session['logged_in'] = False
	return  redirect(url_for('login'))	

@app.route('/',methods = ['GET','POST'])
@app.route('/admin/register',methods = ['GET','POST'])
def register():
	#app.logger.info("register request")
	#sentry.captureMessage("register request")
	try:
		if session['logged_in']:
			return  redirect(url_for('employee',nexturl="x"))
	except Exception,e:
		print e		

	if request.method == 'POST':
		try:	
			#app.logger.info("data from form submit %s",str(request.form))	
			#sentry.captureMessage("data from form submit ")
			#sentry.captureMessage(str(request.form))		
			username = request.form['username']
			email = request.form['email']	
			companyid = request.form['companyid']	
			apitoken = request.form['apitoken']
			password = request.form['password']				
			#validation unique
			obj1 = CompanyAdmin.query.filter_by(username=username).first()			
			if obj1:
				#app.logger.info("Username Exists. Choose different username")
				mystr = "Username " + username + " Exists. Choose different username"
				sentry.captureMessage(mystr)
				
				return render_template("register.html",message = "Username Exists. Choose different username")
			obj2 = CompanyAdmin.query.filter_by(email=email).first()
			if obj2:
				#app.logger.info("Email Exists. Choose different email")
				mystr = "Email " + email + " Exists. Choose different email"
				sentry.captureMessage(mystr)
				#sentry.captureMessage(email)
				return render_template("register.html",message = "Email Exists. Choose different email")
			
			##################
			hashed = hashpw(str(password), gensalt())		
			u =  CompanyAdmin(username=username,password=hashed,apitoken=apitoken,company_id=companyid,email=email)
			db.session.add(u)		
			db.session.commit()	
			#app.logger.info("data committed to db")
			#sentry.captureMessage("data committed to db")
			return  redirect(url_for('login'))	
			
		except Exception,e:	
			#app.logger.info(str(e))
			mystr = str(e) + "\n" + str(request.form)
			sentry.captureMessage(mystr)
			#sentry.captureMessage()
			return render_template("error.html")
	return render_template("register.html")

@app.route('/admin/login',methods = ['GET','POST'])
def login():
	#app.logger.info("login request")
	#sentry.captureMessage("login request")
	try:
		if session['logged_in']:
			return  redirect(url_for('employee',nexturl="x"))
	except Exception,e:
		print e
		
	if request.method == 'POST':
		try:	
			#app.logger.info("input data = %s",str(request.form)	)	
			#sentry.captureMessage("input data")
			#sentry.captureMessage(str(request.form))
			password = request.form['password']
			username = request.form['username']			
			cobj = CompanyAdmin.query.filter_by(username=username).first()		
			if not cobj:
				#app.logger.info("Username does not exist")
				mystr = "Username does not exist" + "\n" + str(request.form)
				sentry.captureMessage(mystr)
				#sentry.captureMessage("Username does not exist")
				return render_template("adminlogin2.html",message="Username does not exist")	
			if hashpw(str(password), str(cobj.password)) == cobj.password:				
				session['logged_in'] = True
				session['username'] = username				
				ret_users = []				
				#sentry.captureMessage("user logged in")
				#app.logger.info("user logged in")
				return  redirect(url_for('employee',nexturl="x"))
			else:		
				sentry.captureMessage("Wrong Credentials. Please try again")
				#app.logger.info("Wrong Credentials. Please try again")
				return render_template("adminlogin2.html",message="Wrong Credentials. Please try again")
		except Exception,e:
			mystr = str(e) + "\n" + str(request.form)
			sentry.captureMessage(mystr)			
			#app.logger.info(str(e))	
			return render_template("error.html")
	return render_template("adminlogin2.html")

def get_department(url):	
	if url != None:
		try:
			mydict = fetch_from_cache(url)
			return mydict["data"]["name"]
		except Exception,e:
			print e
			return ""
	else:
		return ""
def get_location(url):
	if url != None:
		try:
			mydict = fetch_from_cache(url)
			return mydict["data"]["name"]
		except Exception,e:
			print e
			return ""
	else:
		return ""
def get_manager(url):
	if url != None:
		try:
			mydict = fetch_from_cache(url)
			return (mydict["data"]["first_name"] + mydict["data"]["last_name"])
		except Exception,e:
			print e
			return ""
	else:
		return ""


@app.route('/employee',methods = ['GET'])
def employee():
	try:			
		#app.logger.info("get employee data")
		#sentry.captureMessage("get employee data")
		#app.logger.info(session['username'])
		#sentry.captureMessage(session['username'])
		cobj = CompanyAdmin.query.filter_by(username=session['username']).first()
		cid = cobj.company_id
		token = "Bearer " + cobj.apitoken		

		if request.args['nexturl'] == "x":
			url = "https://api.zenefits.com/core/companies/" +str(cid) + "/people"
		else:		
			next_url_rcvd = utils.decode(cobj.apitoken,str(request.args['nexturl']))				
			url = next_url_rcvd
		#app.logger.info(url)
		#sentry.captureMessage(url)
		headers = {'authorization': token}
		response = requests.request("GET", url, headers=headers)
		ret = response.text		
		empdict = json.loads(ret)
		users = []
		for employee in empdict["data"]["data"]:
			user = {}
			first_name = employee["first_name"] if employee["first_name"]  else ""
			middle_name = employee["middle_name"] if employee["middle_name"]  else ""
			last_name = employee["last_name"] if employee["last_name"]  else ""
			user["fullname"] = first_name + " " +  middle_name +" " + last_name
			user["title"] = employee["title"] if employee["title"] else ""			
			####
			user["department"] = get_department(employee["department"]["url"])
			user["location"] = get_location(employee["location"]["url"])
			user["manager"] = get_manager(employee["manager"]["url"])
			####			
			user["email"] =  employee["work_email"] if employee["work_email"] else ""
			users.append(user)
		
		if empdict["data"]["next_url"] == None:
			#sentry.captureMessage("next url none. end of pagination")
			#app.logger.info("next url none. end of pagination")
			return render_template("listing.html",users=users)
		else:
			#sentry.captureMessage("next url passed")
			#app.logger.info("next url passed")
			
			next_url_fetched = empdict["data"]["next_url"]
			#app.logger.info(next_url_fetched)
			#sentry.captureMessage(next_url_fetched)
			nexturlencoded = utils.encode(cobj.apitoken,next_url_fetched)
		
			return render_template("listing.html",users=users,nexturl=nexturlencoded)
	except Exception,e:
		#app.logger.info(str(e))
		sentry.captureMessage(str(e))
		return render_template("error.html")

db.create_all()
