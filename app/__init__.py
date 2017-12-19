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

#for memcache
import memcache
client = memcache.Client([('127.0.0.1', 11211)])

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

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://' + mysql_username + ':' + mysql_password + '@' + mysql_host + '/' + mysql_db
db = SQLAlchemy(app)
lm = LoginManager(app)
lm.login_view = '/admin/login'


class CompanyAdmin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)
    apitoken = db.Column(db.String(120), unique=True, nullable=True)
    company_id = db.Column(db.Integer,unique=True, nullable=False)

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
    session['logged_in'] = False
    return  render_template('adminlogin2.html',message="logout")


@app.route('/admin/register',methods = ['POST'])
def register():
	try:		
		val =  json.loads(request.data)		
		hashed = hashpw(str(val["password"]), gensalt())		
		u =  CompanyAdmin(username=val["username"],password=hashed,apitoken=val["apitoken"],company_id=val["company_id"],email=val["email"])
		db.session.add(u)		
		db.session.commit()		
		ret = {"status":"success"}
		return json.dumps(ret)
	except Exception,e:		
		ret = {"status":"failure"}
		return json.dumps(ret)

@app.route('/admin/login',methods = ['GET','POST'])
def login():
	if request.method == 'POST':
		try:				
			password = request.form['password']
			username = request.form['username']			
			cobj = CompanyAdmin.query.filter_by(username=username).first()			
			if hashpw(str(password), str(cobj.password)) == cobj.password:				
				session['logged_in'] = True
				session['username'] = username				
				ret_users = []
				return  redirect(url_for('employee',nexturl="x"))
			else:		
				return render_template("adminlogin2.html",message="Wrong Credentials. Please try again")
		except Exception,e:
			print e		
			ret = {"status":"failure"}
			return json.dumps(ret)
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
		cobj = CompanyAdmin.query.filter_by(username=session['username']).first()
		cid = cobj.company_id
		token = "Bearer " + cobj.apitoken		

		if request.args['nexturl'] == "x":
			url = "https://api.zenefits.com/core/companies/" +str(cid) + "/people"
		else:		
			next_url_rcvd = utils.decode(cobj.apitoken,str(request.args['nexturl']))				
			url = next_url_rcvd
		
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
			return render_template("listing.html",users=users)
		else:
			next_url_fetched = empdict["data"]["next_url"]
			nexturlencoded = utils.encode(cobj.apitoken,next_url_fetched)
		
			return render_template("listing.html",users=users,nexturl=nexturlencoded)
	except Exception,e:
		print e
		ret = {"status":"failure"}
		return json.dumps(ret)

db.create_all()
