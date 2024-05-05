import os

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from flask import url_for

import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
from flask_sqlalchemy import SQLAlchemy
import numpy as np
from datetime import datetime, timedelta
from sqlalchemy import desc
import bcrypt
import re

app = Flask(__name__)
app.secret_key = "super secret key"

db = SQLAlchemy()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pandas.db"
db.init_app(app)

class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.Text, nullable=False)
    company_name = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.Text, nullable=False)
    salary = db.Column(db.Integer, nullable=False)
    username = db.Column(db.Text, nullable=False)
    status = db.Column(db.Text, nullable=False)
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.now)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()
    db.session.commit()


def is_valid_password(password):
    # min 8 characters
    if len(password) < 8:
        return False
    # uppercase check
    if not re.search(r"[A-Z]", password):
        return False
    # lowercase check
    if not re.search(r"[a-z]", password):
        return False
    # digit check
    if not re.search(r"\d", password):
        return False
    return True


@app.route("/")
@app.route("/home")
def index():
    if 'user_id' in session:
        return render_template("home.html")
    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form['uname']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template("login.html", error="Passwords do not match")
        
        if not is_valid_password(password):
            return render_template("login.html", error="Password does not meet complexity requirements")

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template("login.html", error="Username already exists")
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        session["user_id"] = new_user.id

        return render_template("home.html")
    else:
        return render_template("signup.html")

@app.route('/login', methods = ['POST', 'GET'])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form['uname']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user is None or not bcrypt.checkpw(password.encode('utf-8'), user.password):
            return render_template("login.html", error="User does not exist!")

        session["user_id"] = user.id

        return render_template("home.html")
    else:
        return render_template("login.html")


@app.route('/logout', methods = ['POST', 'GET'])
def logout():
    session.clear()
    return redirect("/")


@app.route('/add', methods = ['POST', 'GET'])
def add():
    return render_template("add.html")


@app.route('/add_form', methods = ['POST', 'GET'])
def add_form():
    title = request.form['title']
    company_name = request.form['company_name']
    description = request.form['description']
    location = request.form['location']
    salary = request.form['salary']
    user = session["user_id"]
    status = "applied"

    new_listing = Listing(title=title, company_name=company_name, description=description, location=location, salary=salary, username=user, status=status)
    db.session.add(new_listing)
    db.session.commit()

    return render_template("add.html", added="true")


@app.route('/search_account', methods = ['POST', 'GET'])
def search_account():
    name_search = request.form['company']

    not_found = "No listing found for '" + name_search + "'"
    
    listings = Listing.query.filter(Listing.company_name.ilike(f"%{name_search}%"),Listing.username == session["user_id"]).order_by(desc(Listing.date_added)).all()

    if not listings:
        listings = Listing.query.all()
        return render_template("account.html", not_found=not_found, listings=listings)
    return render_template("account.html", listings=listings)


@app.route('/update_listing_status', methods = ['POST', 'GET'])
def update_listing_status():
    listing_id = request.form['id']
    status = request.form['status']
    
    listing = Listing.query.filter_by(id=listing_id).first()
    
    if listing:
        listing.status = status
        db.session.commit()
        flash('Status updated successfully', 'success')
        
    else:
        flash('Listing not found', 'error')

    user_listings = Listing.query.filter_by(username=session["user_id"]).order_by(desc(Listing.date_added)).all()

    return render_template("account.html", listings=user_listings, update="Job Status Updated")


@app.route('/delete_listing', methods=['POST'])
def delete_listing():
    listing_id = request.form['id']
    
    listing = Listing.query.get(listing_id)
    
    if listing:
        db.session.delete(listing)
        db.session.commit()
        

    user_listings = Listing.query.filter_by(username=session["user_id"]).order_by(desc(Listing.date_added)).all()

    return render_template("account.html", listings=user_listings, update="Job Deleted")

@app.route('/visualise', methods=['GET'])
def visualise():
    timePeriod = request.args.get("time-period")
    if timePeriod:
        if timePeriod == "today":
            timeFrame = datetime.now() - timedelta(hours=24)
        elif timePeriod == "last7":
            timeFrame = datetime.now() - timedelta(days=7)
        elif timePeriod == "last30":
            timeFrame = datetime.now() - timedelta(days=30)
        else:
            timeFrame = datetime.now() - timedelta(days=365)
        listings = Listing.query.filter(Listing.date_added >= timeFrame,Listing.username == session["user_id"]).all()
    else:
        listings = Listing.query.filter_by(username=session["user_id"]).all()  

    descriptions = [listing.description for listing in listings]
    df = pd.DataFrame({'description': descriptions})

    software_engineering_skills = [
    'CMS', 'python', 'javascript', 'html', 'css', 'bootstrap', 'java', 'javascript', 'c++', 'c#', 'html', 'css', 'sql', 'git', 'docker', 'aws', 'linux',
    'agile', 'scrum', 'oop', 'mvc', 'rest', 'api', 'frontend', 'backend', 'full stack', 'typescript',
    'react', 'angular', 'vue', 'node.js', 'express', 'spring', 'django', 'flask', 'hibernate', 'jquery',
    'bootstrap', 'sass', 'less', 'webpack', 'babel', 'mysql', 'postgresql', 'mongodb', 'nosql', 'graphql',
    'redis', 'kubernetes', 'jenkins', 'continuous integration', 'continuous deployment', 'jira', 'slack',
    'docker-compose', 'apache', 'nginx', 'json', 'xml', 'yaml', 'bash', 'shell scripting', 'unit testing',
    'integration testing', 'functional testing', 'load testing', 'security testing', 'code review', 'debugging',
    'design patterns', 'refactoring', 'clean code', 'agile methodologies', 'software architecture', 'microservices',
    'distributed systems', 'cloud computing', 'devops', 'sdlc', 'version control', 'gitflow', 'test-driven development',
    'pair programming', 'agile ceremonies', 'agile frameworks', 'dependency injection', 'software design', 'algorithms',
    'data structures', 'big o notation', 'software development', 'web development', 'mobile development',
    'machine learning', 'artificial intelligence', 'natural language processing', 'computer vision', 'data science',
    'data engineering', 'deep learning', 'neural networks', 'reinforcement learning', 'tensorflow', 'pytorch',
    'pandas', 'numpy', 'matplotlib', 'scikit-learn', 'keras', 'opencv', 'sqlalchemy', 'beautifulsoup', 'requests',
    'pytest', 'unittest', 'puppeteer', 'selenium', 'jenkins', 'travis ci', 'circle ci', 'gitlab ci', 'sonarqube',
    'eslint', 'prettier', 'typescript', 'babel', 'webpack', 'gulp', 'grunt', 'npm', 'yarn', 'conda', 'virtualenv',
    'pip', 'conda', 'docker-compose', 'kubernetes', 'terraform', 'ansible', 'chef', 'puppet', 'saltstack', 'vagrant',
    'amazon s3', 'google cloud storage', 'azure storage', 'elastic search', 'kibana', 'splunk', 'grafana', 'prometheus',
    'nagios', 'new relic', 'datadog', 'aws cloudwatch', 'azure monitor', 'gcp monitoring', 'git', 'svn', 'mercurial',
    'perforce', 'bitbucket', 'github', 'gitlab', 'azure devops', 'atlassian', 'slack', 'jira', 'confluence', 'trello',
    'asana', 'basecamp', 'notion', 'microsoft teams', 'skype', 'zoom', 'webex', 'figma', 'adobe xd', 'sketch',
    'invision', 'zeplin', 'microsoft office', 'google workspace', 'zoom', 'slack', 'asana', 'trello', 'jira',
    'github', 'gitlab', 'bitbucket', 'azure devops', 'scrum', 'agile', 'kanban', 'lean', 'waterfall', 'xp', 'devops',
    'ci/cd', 'tdd', 'bdd', 'ddd', 'pair programming', 'code review', 'sdlc', 'soa', 'microservices', 'monolith',
    'serverless', 'rest', 'soap', 'graphql', 'apis', 'mqtt', 'amqp', 'zeromq', 'grpc', 'json-rpc', 'xml-rpc',
    'rabbitmq', 'kafka', 'redis', 'memcached', 'mongodb', 'couchbase', 'cassandra', 'dynamodb', 'mysql', 'postgresql',
    'sqlite', 'oracle', 'mssql', 'etl', 'elasticsearch', 'kibana', 'logstash', 'fluentd', 'splunk', 'graylog',
    'prometheus', 'grafana', 'datadog', 'new relic', 'azure monitor', 'aws cloudwatch', 'gcp monitoring', 'uptime',
    'latency', 'availability', 'scalability', 'reliability', 'resilience', 'fault tolerance', 'load balancing',
    'caching', 'indexing', 'encryption', 'authentication', 'authorization', 'oauth', 'jwt', 'ssl/tls', 'cors',
    'csrf', 'sso', 'openid connect', 'ldap', 'ad', 'rbac', 'abac', 'iam', 'devsecops', 'secdevops', 'shift left',
    'vulnerability management', 'penetration testing', 'security audits', 'compliance', 'gdpr', 'hipaa', 'pci-dss',
    'sox', 'nist', 'iso/iec', 'nist', 'nist cybersecurity framework', 'nist sp 800-53', 'nist sp 800-171', 'owasp',
    'owasp top 10', 'cwe', 'sast', 'dast', 'iaast', 'containerization', 'orchestration', 'microsegmentation',
    'firewalls', 'waf', 'ids', 'ips', 'siem', 'encryption', 'vpn', 'dmz', 'bastion host', 'multi-factor authentication',
    'auditing', 'monitoring', 'logging', 'access controls', 'incident response', 'disaster recovery', 'business continuity',
    'risk assessment', 'threat modeling', 'security policies', 'security standards', 'regulatory compliance',
    'secure coding', 'security architecture', 'security testing', 'vulnerability management', 'cloud security',
    'network security', 'application security', 'data security', 'endpoint security', 'identity and access management',
    'container security', 'server security', 'workstation security', 'mobile device security', 'iot security',
    'wireless security', 'physical security', 'data privacy', 'gdpr compliance', 'hipaa compliance', 'pci-dss compliance', 
    'WCAG', 'WCAG', 'UAAG', 'ARIA', 'SEO'
]
    all_descriptions = ' '.join(df['description'])

    words = all_descriptions.lower().split()

    filtered_words = [word for word in words if not any(char.isdigit() for char in word) and word in software_engineering_skills]

    skill_counts = Counter(filtered_words)

    result = skill_counts.most_common(20)


    dates_added = [listing.date_added.date() for listing in listings]     
    date_strings = [str(date) for date in dates_added]
    df = pd.DataFrame({'day': date_strings})
    all_days = ' '.join(df['day'])
    date_split = all_days.split()
    date_counts = Counter(date_split)
    date_results = date_counts.most_common()
    
    date_results = date_results

    salaries = [listing.salary for listing in listings]

    df = pd.DataFrame({'salary': salaries})

    all_salaries = ' '.join(df['salary'])

    salaries_split = all_salaries.lower().split()

    salaries_array = [
    'undisclosed', '£20,000-£30,000', '£30,000-£40,000', '£40,000-£50,000', '£50,000-£60,000', '£60,000-£70,000', '£70,000+'
    ]

    filtered_salaries = [word for word in salaries_split if word in salaries_array]

    salaries_counts = Counter(filtered_salaries)

    salaries_result = salaries_counts.most_common(100)


    status = [listing.status for listing in listings]

    df = pd.DataFrame({'status': status})


    status_array = [
    'applied', 'rejected', 'interview', 'offer-received', 'offer-accepted'
    ]

    filtered_status = [word for word in status if word in status_array]

    status_counts = Counter(filtered_status)

    status_result = status_counts.most_common(100)

    return render_template("visualise.html", result=result, locations_result=date_results, salaries_result=salaries_result, status_result=status_result, timePeriod=timePeriod)



@app.route('/account', methods=['GET'])
def account():
    user_listings = Listing.query.filter_by(username=session["user_id"]).order_by(desc(Listing.date_added)).all()
    return render_template("account.html", listings=user_listings)

if __name__ == '__main__':
    app.run(debug=True)