from dotenv import load_dotenv
load_dotenv()  

from flask import Flask, render_template, request, flash, make_response, g,  redirect, url_for, send_file, jsonify, send_from_directory
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from functools import wraps

import concurrent.futures
import json
import re
from io import BytesIO
import pandas as pd
import requests
from io import StringIO
from urllib.parse import urlparse, urlunparse
import csv
import sys
from newspaper import Article, Config
import sqlite3
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from collections import Counter
import io
import zipfile
import numpy as np
import traceback
import os
import ast
import bleach
import logging

# Paramaterizable Variables
SERP_API_KEY = os.getenv('SERP_API_KEY')
SITES_OF_CONCERN = os.getenv('SITES_OF_CONCERN', '')
KNOWN_INDICATORS = os.getenv('KNOWN_INDICATORS', '')
MYIPMS_API_PATH = os.getenv('MYIPMS_API_PATH', '')
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY', '')
SQLLITE_DB_PATH = os.getenv('SQLLITE_DB_PATH', '')
COPYSCAPE_API_KEY = os.getenv('COPYSCAPE_API_KEY', '')
COPYSCAPE_USER = os.getenv('COPYSCAPE_USER', '')
PATH_TO_OUTPUT_CSV = os.getenv('PATH_TO_OUTPUT_CSV', '')
MATCH_VALUES_TO_IGNORE = os.getenv('MATCH_VALUES_TO_IGNORE', '')
CURRENT_ENVIRONMENT = os.getenv('CURRENT_ENVIRONMENT', 'production')
GCAPTCHA_SECRET = os.getenv('GCAPTCHA_SECRET', '')


from modules.reference import DEFAULTS, ENGINES, LANGUAGES, COUNTRIES, LANGUAGES_YANDEX, LANGUAGES_YAHOO, COUNTRIES_YAHOO, COUNTRY_LANGUAGE_DUCKDUCKGO, DOMAINS_GOOGLE, INDICATOR_METADATA, MATCH_VALUES_TO_IGNORE
# Import all your functions here
from modules.crawler import crawl_one_or_more_urls, annotate_indicators
from modules.matcher import find_matches
from modules.email_utils import send_results_email

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
bootstrap = Bootstrap(app)
bcrypt = Bcrypt(app)
app.secret_key = APP_SECRET_KEY  # Set a secret key for security purposes
app.config['DEBUG'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(filename='debug.log',
                        level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s'
                        )


DATABASE = 'database.db'

#### USER METHODS ####
# TODO: Move to separate file
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    @classmethod
    def get(cls, id):
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (id,))
        user = cursor.fetchone()
        if user:
            return cls(id=user[0], username=user[1], password=user[2])
        return None


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(SQLLITE_DB_PATH)
        # This enables column access by name: row['column_name']
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        # Insert local_domains into sites_base
        insert_sites_of_concern(load_domains_of_concern())


def insert_sites_of_concern(local_domains):
    db = get_db()
    app.logger.info("Inserting indicators: %s", local_domains)
    # Check if the table is empty
    if db.execute('SELECT COUNT(*) FROM sites_base').fetchone()[0] == 0:
        # If empty, insert the local_domains
        db.executemany('INSERT INTO sites_base (domain, source) VALUES (?, ?)',
                       [(domain, source) for domain, source in local_domains])
        db.commit()


def insert_indicators(indicators):
    db = get_db()
    app.logger.info("Inserting indicators: %s", indicators)

    # If empty, insert the local_domains
    db.executemany('INSERT INTO site_fingerprint (domain_name, indicator_type, indicator_content) VALUES (?, ?, ?)',
                   [(indicator['domain_name'], indicator['indicator_type'], str(indicator['indicator_content'])) for indicator in indicators])
    db.commit()

# TODO move to a utils or decorators file
def clean_inputs(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        app.logger.info("Request Info: %s", request)

        # Clean query parameters
        cleaned_args = {}
        for key, values in request.args.lists():
            cleaned_values = [bleach.clean(value) for value in values]
            # If there's only one item, just get the item, not a list
            request.args = request.args.copy()
            request.args[key] = cleaned_values if len(cleaned_values) > 1 else cleaned_values[0]

        # Clean form data
        cleaned_form = {}
        for key, values in request.form.lists():     
            cleaned_values = [bleach.clean(value) for value in values]
            request.form = request.form.copy()
            request.form[key] = cleaned_values if len(cleaned_values) > 1 else cleaned_values[0]

        # You can then pass these cleaned dicts to your view function
        # For demonstration, adding them to kwargs

        return view_func(*args, **kwargs)

    return decorated_function

#### ROUTES ####


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

@app.route('/api/', methods=['GET'])
@app.route('/api/metadata', methods=['GET'])
def index_api():
    return jsonify({'defaults':DEFAULTS,'engines': ENGINES, 'countries': COUNTRIES, 'languages': LANGUAGES, 'indicator_metadata': INDICATOR_METADATA})

## LOGIN/LOGOUT ROUTES##
@app.route('/login', methods=['GET', 'POST'])
@clean_inputs
def login_gui():
    if request.method == 'POST':
        if login(request):
            return redirect(url_for('index'))
        
        return 'Invalid username or password'
    return render_template('login.html')


@app.route('/api/login', methods=['POST'])
@clean_inputs
def login_api():
    if request.method == 'POST':
        if login(request):
            return jsonify({'message': 'Logged in successfully'})
    return jsonify({'message': 'Invalid username or password'})

def login(request):
    is_logged_in = False
    username = request.form['username']
    password = request.form['password']
    reg_key = request.form.get('reg_key', None)


    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if reg_key is not None and user is None: 
        cursor.execute("SELECT registration_keys FROM registration_keys where registration_keys = ?", (reg_key,))
        reg_key_db = cursor.fetchone()
        if reg_key_db is not None:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                        (username, hashed_password))
            db.commit()
            user_obj = User(id=cursor.lastrowid, username=username, password=hashed_password)
            login_user(user_obj)
            is_logged_in = True
        
    elif user and bcrypt.check_password_hash(user['password'], password):
        user_obj = User(
            id=user['id'], username=user['username'], password=user['password'])
        login_user(user_obj)
        is_logged_in = True
    else:
        app.logger.warning('Unauthorized login attempt for user: %s', username)
    return is_logged_in

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out'

@app.route('/api/logout')
@login_required
def logout_api():
    logout_user()
    return jsonify({'message': 'Logged out'})


@app.route('/register', methods=['GET','POST'])
@clean_inputs
def register_gui():
    is_logged_in = False
    username = request.form['username']
    password = request.form['password']
    reg_key = request.form['reg_key']

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT registration_keys FROM registration_keys", (reg_key,))
    reg_keys = cursor.fetchall
    if reg_key in reg_keys:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, hashed_password))
        db.commit()
        user_obj = User(id=cursor.lastrowid, username=username, password=hashed_password)
        login_user(user_obj)
        is_logged_in = True
    else:
        app.logger.warning('Unauthorized login attempt for user: %s', username)
    return render_template('index.html', engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

@app.route('/api/register', methods=['POST'])
@clean_inputs
def register_api():
    return register(request)

def register(request):
    username = request.form['username']
    plain_text_password = request.form['password']
    hashed_password = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')
    # Save the username and hashed_password to the database
    return jsonify({'message': 'Registered successfully'})

@app.route('/url-search', methods=[ 'POST'])
@clean_inputs
def url_search():
    try:
        indicators_df, matches_df, indicator_summary, matches_summary = fingerprint(request)

        return render_template('index.html', engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA, indicators_df=indicators_df.to_dict('records'), matches_df=matches_df.to_dict('records'), indicator_summary = indicator_summary, matches_summary = matches_summary)
    except Exception as e:
        return render_template('error.html', errorx=e, errortrace=traceback.format_exc())
    
#deprecated
@app.route('/fingerprint', methods=['GET', 'POST'])
#@login_required
@clean_inputs
def fingerprint_gui():
    if request.method == 'POST':
        try:
            indicators_df, matches_df, indicator_summary, matches_summary = fingerprint(request)
            return render_template('index.html',  countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA, indicators_df=indicators_df.to_dict('records'), matches_df=matches_df.to_dict('records'), indicator_summary = indicator_summary, matches_summary = matches_summary)
        except Exception as e:
            return render_template('error.html', errorx=e, errortrace=traceback.format_exc())
    return render_template('index.html', request=request, engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

@app.route('/api/fingerprint', methods=['POST'])
#@login_required
@clean_inputs
def fingerprint_api():
    if request.method == 'POST':
        try:
            indicators_df, matches_df, indicator_summary, matches_summary = fingerprint(request)
            return jsonify({'countries': COUNTRIES, 'languages': LANGUAGES, 'indicator_metadata': INDICATOR_METADATA, 'indicators': indicators_df.to_dict('records'), 'matches': matches_df.to_dict('records'), 'indicator_summary': indicator_summary, 'matches_summary': matches_summary})
        except Exception as e:
            return jsonify({'error': e, 'trace': traceback.format_exc()})
    return jsonify({'error': 'No URL provided'})

def fingerprint(request):
    url = request.form['url']
    run_urlscan =  'run_urlscan' in request.form
    internal_only = 'internal_only' in request.form
    urls = url_string_to_valid_urls(url)
    return find_indicators_and_matches(urls, run_urlscan = run_urlscan, internal_only = internal_only)

def find_indicators_and_matches(urls, run_urlscan = False, internal_only = False):
    indicators = crawl_one_or_more_urls(urls, run_urlscan = run_urlscan)
    indicator_summary = summarize_indicators(indicators)
    indicators_df = pd.DataFrame([o.__dict__ for o in indicators])
    indicators_df = indicators_df.rename(columns={'content': 'indicator_content', 'domain': 'domain_name', 'type': 'indicator_type'})
    filter_mask = ~indicators_df['indicator_content'].isin(MATCH_VALUES_TO_IGNORE)
    indicators_df = indicators_df[filter_mask]
    indicators_df = annotate_indicators(indicators_df)

    if internal_only:
        comparison_indicators = indicators_df
    else:
        comparison_indicators = pd.read_csv(
            KNOWN_INDICATORS)  # read the csv file
        
        comparison_indicators = pd.concat([indicators_df, comparison_indicators])
    filter_mask = ~comparison_indicators['indicator_content'].isin(MATCH_VALUES_TO_IGNORE)
    comparison_indicators = comparison_indicators[filter_mask]
    # print(indicators_df.head(), comparison_indicators.head())
    # Find matches
    # Split DataFrame into smaller DataFrames based on 'domain'
    grouped_indicators = indicators_df.groupby('domain_name')

    # Create a dictionary to store each group as a DataFrame
    grouped_indicators_dfs = {group: data for group, data in grouped_indicators}
    
    matches_df = pd.DataFrame()
    for group, grouped_indicators_df in grouped_indicators_dfs.items():
        grouped_matches_df = find_matches(grouped_indicators_df, comparison=comparison_indicators)
        matches_df = pd.concat([matches_df, grouped_matches_df])
    matches_df.reset_index(drop=True, inplace=True)
    matches_df = matches_df.replace({np.nan: None})
    matches_df = matches_df.applymap(convert_sets_to_lists)
    matches_summary = summarize_indicators(matches_df.to_dict('records'), column='match_type')

    return indicators_df, matches_df, indicator_summary, matches_summary

def convert_sets_to_lists(item):
    if isinstance(item, set):
        return list(item)
    else:
        return item

@app.route('/content', methods=['GET', 'POST'])
@clean_inputs
def content_gui():
    if request.method == 'POST':
        if not request.form.get('titleQuery') and not request.form.get('contentQuery'):
            # Error message if neither is provided
            flash("Please provide at least a title or content query.")
        else:
            results, csv_data = (None, None)
            results, csv_data = content(request)
            
    return render_template('index.html', results=results, csv_data=csv_data, engines=ENGINES,  countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

@app.route('/api/content', methods=['POST'])
@clean_inputs
def content_api():
    if request.method == 'POST':
        if not request.form.get('titleQuery') and not request.form.get('contentQuery'):
            # Error message if neither is provided
            return jsonify({'error': 'Please provide at least a title or content query.'})
        else:
            results, csv_data = content(request)
            return jsonify({'results': results, 'csv_data': csv_data, 'countries': COUNTRIES, 'languages': LANGUAGES, 'indicator_metadata': INDICATOR_METADATA})

@app.route('/content-search', methods=['POST'])
@app.route('/api/content-search', methods=['POST'])
@clean_inputs
def parse_content_search():
    if request.method == 'POST':
        contentToSearch = request.form.get('contentToSearch')
        isApi = request.form.get('isApi', 'false')
        # Parse the URL
        parsed_url = format_url(contentToSearch)
        if parsed_url is not None: 
            results, csv_data = parse_url(request, contentToSearch)
        else:
            title_query, content_query = parse_title_content(contentToSearch)
            results, csv_data = content(request, title_query, content_query)
        if isApi == 'true':
            return jsonify({'results': results, 'csv_data': csv_data, 'countries': COUNTRIES, 'languages': LANGUAGES, 'indicator_metadata': INDICATOR_METADATA})
        else:
            return render_template('index.html', request=request, results=results, csv_data=csv_data, engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

def content(request, title_query=None, content_query=None):
    title_query = title_query if title_query is not None else  request.form.get('titleQuery')
    content_query = content_query if content_query is not None else request.form.get('contentQuery')
    combineOperator = request.form.get('combineOperator', 'OR')
    language = request.form.get('language', 'en') 
    country = request.form.get('country', 'us') 
    engines = request.form.getlist('search_engines')

    print("Engines: ", engines, "Title Query: ", title_query, "Content Query: ", content_query, "Combine Operator: ", combineOperator, "Language: ", language, "Country: ", country)
    if engines == 'all' or engines == ['all'] or engines == []:
        engines = ['google', 'google_news', 'bing', 'bing_news', 'duckduckgo', 'yahoo', 'yandex', 'gdelt', 'copyscape']
    if isinstance(engines, str):
        engines = [engines]

    if any(isinstance(sublist, list) for sublist in engines):
        engines = [item for sublist in engines for item in sublist]  
    if combineOperator == 'False' or combineOperator == 'false':
        combineOperator = 'OR'
    elif combineOperator == 'True' or combineOperator == 'true':
        combineOperator = 'AND'

        # Extracting article data-
    if not title_query and not content_query:
        # Error message if neither is provided
        return jsonify({'error': 'Please provide at least a title or content query.'})
    else:
        return fetch_content_results(
            title_query, content_query, combineOperator, language, country, engines=engines)

#Deprecated
@app.route('/parse-url', methods=['POST'])
@clean_inputs
def parse_url_gui():
    url = request.form['url']
    url = format_url(url)

    if not url:
        return render_template('index.html', engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)
    try:
        results, csv_data = parse_url(request)
        return render_template('index.html', results=results, csv_data=csv_data, engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)
    except Exception as e:
        response = requests.get(url)
        if response.status_code == 200:
            # Parse the HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_title = soup.title.string or soup.find('meta', attrs={'name': 'title'})['content'] if soup.title else "" 
            meta_description = soup.find('meta', attrs={'name': 'description'})['content'] if soup.find('meta', attrs={'name': 'description'}) else ""
            flash(f"This page could not automatically be parsed for content, but a potential title and first paragraph have been extracted, copy and paste those below if correct: {meta_title} : {meta_description}")

        else:
            flash("This page could not automatically be parsed for content. Please enter a title and/or content query manually.")
        
        return render_template('index.html', engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)
    
@app.route('/api/parse-url', methods=['POST'])
@clean_inputs
def parse_url_api():
    try:
        results, csv_data = parse_url(request)
        return jsonify({'results': results, 'csv_data': csv_data, 'countries': COUNTRIES, 'languages': LANGUAGES, 'indicator_metadata': INDICATOR_METADATA})
    
    except Exception as e:
        return jsonify({'error': "This page could not automatically be parsed for content. Please enter a title and/or content query manually."})
        
def parse_url(request, urlToParse=None):
    url = urlToParse if urlToParse is not None else request.form.get('url', '')
    url = format_url(url)
    engines = request.form.getlist('search_engines')
    combineOperator = request.form.get('combineOperator', 'OR')
    language = request.form.get('language', 'en')
    country = request.form.get('country', 'us')
    if engines == 'all' or engines == ['all'] or engines == []:
        engines = ['google', 'google_news', 'bing', 'bing_news', 'duckduckgo', 'yahoo', 'yandex', 'gdelt', 'copyscape']
    if isinstance(engines, str):
        engines = [engines]
    if any(isinstance(sublist, list) for sublist in engines):
        engines = [item for sublist in engines for item in sublist]
    if combineOperator == 'False' or combineOperator == 'false':
        combineOperator = 'OR'
    elif combineOperator == 'True' or combineOperator == 'true':
        combineOperator = 'AND'

        # Extracting article data-
    try:
        
        article = Article(url)
        article.download()
        article.parse()

        return fetch_content_results(
                article.title, article.text, combineOperator, language, country, engines=engines)
    #TODO: Add error handling on the frontend
    except Exception as e:
        return jsonify({'error': "This page could not automatically be parsed for content. Please enter a title and/or content query manually."})

@app.route('/batch-search-metadata', methods=['POST'])
@clean_inputs
def parse_batch_search_metadata():
    if request.files['fingerprint-file'].filename != '':
        return fingerprint_file(request)
    
@app.route('/batch-search-content', methods=['POST'])
@clean_inputs
def parse_batch_search_content():
    if request.files['file'].filename != '':
        return upload_file(request)

@app.route('/content-csv', methods=['POST'])
@clean_inputs
def upload_file_gui():
    return upload_file(request)
   
@app.route('/api/content-csv', methods=['POST'])    
@clean_inputs
def upload_file_api():
    return upload_file(request)
    # return jsonify({'message': 'File processed successfully'})

def upload_file(request):
    file = request.files['file']
    email_recipient = request.form.get('email')
    if file.filename != '':
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline='')
        csv_input = csv.DictReader(stream)
        # Use StringIO to create an in-memory file-like object
        output_stream = io.StringIO()


        results_df = pd.DataFrame(columns=['SearchedURL', 'SearchedTitle', 'SearchedContent', 'Domain', 'Source', 'URL', 'Title', 'Snippet', 'LinkCount', 'Engines', 'DomainCount', 'Score'])

        # Process each URL in the CSV
        for row in csv_input:
            searched_url = row.get("url")
            title_query = row.get("title")
            content_query = row.get("content")
            combineOperator = row.get("combineOperator")
            language = row.get("language")
            country = row.get("country")
            engines = row.get("engines").split(',')
            if engines == ['all'] or engines == [] or engines == '':
                engines = ['google', 'google_news', 'bing', 'bing_news', 'yahoo', 'duckduckgo', 'yandex', 'gdelt', 'copyscape']
            if language == '':
                language = 'en'
            if country == '':
                country = 'us'
            if combineOperator == 'False' or combineOperator == 'false':
                combineOperator = 'OR'
            elif combineOperator == 'True' or combineOperator == 'true':
                combineOperator = 'AND'
            try:
                if title_query is not None or content_query is not None :

                    title_query = row.get("title")
                    content_query = row.get("content")

                    results, csv_data = fetch_content_results(
                        title_query, content_query, combineOperator,  language, country, engines=engines)

                elif searched_url:
                    user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0) Gecko/20100101 Firefox/78.0'

                    searched_url = format_url(searched_url)
                    config = Config()
                    config.browser_user_agent = user_agent
                    config.request_timeout = 15

                    article = Article(searched_url, config=config)
                    article.download()
                    article.parse()
                    logging.debug(f"Processing article: {article.title} for {engines}")

                    #todo: add language and country from csv
                    results, csv_data = fetch_content_results(article.title, article.text, combineOperator, language, country, engines=engines)
                # Initialize an empty list to hold all the new rows
                all_new_rows = []

                # Loop through the results and create a list of new rows
                for result in results:
                    logging.debug(f"Processing result: {result}")
                    new_row = [searched_url,
                            title_query, 
                            content_query,
                            result['domain'],
                            ', '.join(result['source']),
                            result['url'],
                            result['title'],
                            result['snippet'],
                            result['link_count'],
                            ', '.join(result['engines']),
                            result['domain_count'],
                            result['score']]
                    
                    all_new_rows.append(new_row)

                # Create a DataFrame from the list of new rows
                new_rows_df = pd.DataFrame(all_new_rows, columns=results_df.columns)

                # Concatenate this new DataFrame with the existing one
                results_df = pd.concat([results_df, new_rows_df], ignore_index=True)

            except Exception as e:
                app.logger.error(f"Error processing {searched_url}: {e}")
                print(f"Error processing {searched_url}: {e}, continuing...")
                        # Reset file pointer to the beginning
                results_df.to_csv('out_partial.csv', index=False)

                continue

        # Reset file pointer to the beginning
        results_df.to_csv(output_stream, index=False)
        output_stream.seek(0) 
        try:
            send_results_email(email_recipient, "Disinfo Laundromat Results", "Please find the results from the Disinfo Laundromat analysis attached. ", io.BytesIO(output_stream.getvalue().encode()), 'laundromat_content_results.csv')
        except Exception as e:
            app.logger.error(f"Error sending email: {e}")
            print(f"Error sending email: {e}, continuing...")
        finally:
            bytes_stream = io.BytesIO(output_stream.getvalue().encode())
            #print("Finally Content Results")
            return send_file(
            bytes_stream,
            mimetype='text/csv',
            as_attachment=True,
            download_name='laundromat_content_results.csv'
        )

#TODO: Figure out a way to API-ify this
@app.route('/fingerprint-csv', methods=['POST'])
@clean_inputs
def fingerprint_file_gui():
    return fingerprint_file(request)
    # If no file, render the index template
   # return render_template('index.html', engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

@app.route('/api/fingerprint-csv', methods=['POST'])
@clean_inputs
def fingerprint_file_api():
    return fingerprint_file(request)
    #return jsonify({'message': 'File processed successfully'})

def fingerprint_file(request):
    file = request.files['fingerprint-file']
    internal_only = 'internal_only' in request.form
    email_recipient = request.form.get('email')
    run_urlscan =  'run_urlscan' in request.form
    
    if file:    
        df_urls = pd.read_csv(StringIO(file.read().decode('utf-8')))
        urls = df_urls['url'].tolist()  # Assuming 'Urls' is the column name

        # The find_indicators_and_matches function should be defined elsewhere
        indicators_df, matches_df, indicator_summary, matches_summary = find_indicators_and_matches(urls, internal_only = internal_only, run_urlscan = run_urlscan)

        # Save dataframes as csv in memory
        indicators_csv = StringIO()
        matches_csv = StringIO()
        indicators_df.to_csv(indicators_csv, index=False)
        matches_df.to_csv(matches_csv, index=False)

        indicators_df.to_csv('indicators_partial.csv', index=False)
        
        # Reset the pointer of StringIO objects
        indicators_csv.seek(0)
        matches_csv.seek(0)

        # Create a zip file in memory
        mem_zip = BytesIO()
        with zipfile.ZipFile(mem_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('indicators.csv', indicators_csv.getvalue())
            zf.writestr('matches.csv', matches_csv.getvalue())
        if email_recipient: 
            send_results_email(email_recipient, "Laundromat Results - Batch Metadata", "Please find the results from the Laundromat Metadata analysis attached. Summary: ", mem_zip, 'indicators_and_matches.zip')            
        # Prepare the zip file to send to client
        mem_zip.seek(0)
        return send_file(
            mem_zip,
            mimetype='application/zip',
            as_attachment=True,
            download_name='indicators_and_matches.zip'
        )
    


@app.route('/download_csv', methods=['POST'])
@app.route('/api/download_csv', methods=['POST'])
@clean_inputs
def download_csv():
    csv_data = request.form.get('csv_data', '')

    output = make_response(csv_data)
    output.headers["Content-Disposition"] = "attachment; filename=results.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/indicators')
@clean_inputs
def indicators_gui():
    data, unique_types, selected_type = indicators(request)
    return render_template('indicators.html', data=data, unique_types=unique_types, selected_type=selected_type, indicator_metadata=INDICATOR_METADATA)

@app.route('/about')
@clean_inputs
def about():
    data, unique_types, selected_type = indicators(request)
    return render_template('about.html', data=data, unique_types=unique_types, selected_type=selected_type, indicator_metadata=INDICATOR_METADATA)

@app.route('/domain_labels')
@clean_inputs
def parse_gate_domain_labels(request=None, text=None):
    if request is not None:
        text = request.form.get('text')
    elif text is not None:
        text = text
    else:
        return jsonify({'error': 'No text provided'})

    # Define the API endpoint
    api_url = "https://cloud-api.gate.ac.uk/process/url-domain-analysis"
    payload = {
        "text": text,
        "annotations": ":URL, :SourceCredibility"
    }
    headers = {
    "Content-Type": "text/plain",
    # Add other necessary headers like Authorization if needed
    }   
        # Making a POST request to the API
    response = requests.post(api_url, json=payload, headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        source_credibility = json_response["entities"]["SourceCredibility"]
        domain_labels = {}

        for item in source_credibility:
            domain = item.get("resolved-domain")
            label = item.get("labels")
            if domain:
                if domain in domain_labels:
                    if label not in domain_labels[domain]:
                        domain_labels[domain].append(label)
                else:
                    domain_labels[domain] = [label]

        return  domain_labels
    else:
        return jsonify({'error': f'Error: {response.status_code}'})

@app.route('/download_content_csv_example', methods=['GET'])
def download_content_csv_example():
    directory = os.path.join(app.root_path, 'examples')  # Adjust the path as needed
    filename = 'content_csv_example.csv'
    return send_from_directory(directory, filename, as_attachment=True)


@app.route('/download_domain_metadata_example', methods=['GET'])
def download_domain_metadata_example():
    directory = os.path.join(app.root_path, 'examples')  # Adjust the path as needed
    filename = 'domain_metadata_example.csv'
    return send_from_directory(directory, filename, as_attachment=True)
    
def verify_captcha(request):
     # The response from reCAPTCHA
    captcha_response = request.form['g-recaptcha-response']
    
    # Verify the captcha response
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
        'secret': GCAPTCHA_SECRET,
        'response': captcha_response
    })
    
    response_data = response.json()
    
    if response_data['success']:
        # reCAPTCHA verified successfully
        # Process the rest of your form here
        return True
    else:
        # Failed verification
        return False


@app.route('/api/indicators')
@clean_inputs
def indicators_api():
    # Get the selected type from the query parameters

    data, unique_types, selected_type = indicators(request)
    return jsonify({'data': data, 'unique_types': unique_types, 'selected_type': selected_type, 'indicator_metadata': INDICATOR_METADATA})

def indicators(request):
    selected_type = request.args.get('type', '')
    
    maxInt = sys.maxsize
    while True:
        # decrease the maxInt value by factor 10
        # as long as the OverflowError occurs.
        try:
            csv.field_size_limit(maxInt)
            break
        except OverflowError:
            maxInt = int(maxInt/10)

    data = []
    
    with open(KNOWN_INDICATORS, 'r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        unique_types_list = []
        for row in csv_reader:
            unique_types_list.append(row['indicator_type'])
            if len(selected_type) > 0 and row['indicator_type'] == selected_type:
                truncated_row = {key: value[:100] for key, value in row.items()}
                data.append(truncated_row)
        unique_types = sorted(set(unique_types_list))
    return data, unique_types, selected_type


def filter_gdelt_query(query):
    """
    Remove words of two letters or fewer and non-alphanumeric characters from the query, shortens to 249 characters
    """
    # Remove non-alphanumeric characters
    alphanumeric_query = re.sub(r'\W+', ' ', query)
    # Filter out short words, then truncate to 249 characters, then remove the last word (in case it's cut off)
    filtered_query = ' '.join(word for word in alphanumeric_query.split() if len(word) > 2)
    if len(filtered_query) > 249:
        filtered_query = filtered_query[:248]
        filtered_query = filtered_query[:filtered_query.rfind(' ')]
    return filtered_query

def fetch_copyscape_results(title_query, content_query, combineOperator, language, country):
    """
    Send the query to the COPYSCAPR API and return the parsed JSON response.
    """
    base_url = "https://www.copyscape.com/api/"

    params = {
        'u': COPYSCAPE_USER,
        'k': COPYSCAPE_API_KEY,
        'o': 'csearch',
        'f': 'json',
        'e': 'UTF-8',
        't': re.sub(r'\W+', ' ', title_query + " " + content_query) # Remove non-alphanumeric characters
    }

    try:
        response = requests.post(base_url, data=params)
        response.raise_for_status()  # Raise an error for bad status codes
        results_cs = json.loads(response.text)
        
        if "result" in results_cs and len(results_cs["result"]) > 0:
            results_cs = format_copyscape_output(results_cs['result'])
            return results_cs
        else:
            print("No matches in CopyScape data or an error occurred")
            return None

    except requests.RequestException as e:
        print(f"Error during request: {e}")
        app.logger.error(f"Error during request: {e}")

        return None
    
def fetch_gdelt_results(title_query, content_query, combineOperator, language, country):
    """
    Send the query to the GDELT API and return the parsed JSON response.
    """
    base_url = "https://api.gdeltproject.org/api/v2/doc/doc"
    filtered_query = filter_gdelt_query(title_query + " " + content_query)

    params = {
        "format": "json",
        "timespan": "FULL",
        "query": filtered_query,
        "mode": "artlist",
        "maxrecords": 75,
        "sort": "hybridrel"
    }

    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()  # Raise an error for bad status codes
        results_gdelt = response.json()
        if results_gdelt:
            results_gdelt = format_gdelt_output(results_gdelt)
            return results_gdelt
        else:
            print("No results matched for GDELT data")
            return None

    except requests.RequestException as e:
        app.logger.error(f"Error processing: {e}")
        print(f"Error during request: {e}")
        return None

# Trunk content recievind
def fetch_content_results(title_query, content_query, combineOperator, language, country, engines=['google', 'google_news', 'bing', 'bing_news', 'duckduckgo', 'yahoo', 'yandex', 'gdelt', 'copyscape']):
    
    title_query = truncate_text(title_query)
    content_query = truncate_text(content_query)

    # Parameters for SERPAPI Google integration
    results = fetch_serp_results(
        title_query, content_query, combineOperator, language, country, engines=engines)

    # Convert results to CSV
    csv_data = convert_results_to_csv(results)
    # Save the query to the database

    # db = get_db()
    # cursor = db.cursor()
    # cursor.execute('INSERT INTO content_queries (title_query, content_query, combine_operator, language, country) VALUES (?, ?, ?, ?, ?)',
    #                 (title_query, content_query, combineOperator, language, country))
    # db.commit()
    # # Get the last inserted row ID
    # cq_id = cursor.lastrowid

    # results_list = []
    # for domain, data in results.items():
    #     for link_data in data['links']:
    #         res = [
    #             cq_id,
    #             domain,
    #             str(data['count']),
    #             link_data['title'],
    #             link_data['link'],
    #             str(link_data['count']),
    #             ', '.join(link_data['engines'])
    #         ]
    #         results_list.append(res)

    # # Insert data into the database
    # # Prepare your SQL insert statement including the additional column
    # insert_sql = 'INSERT INTO content_queries_results (cq_id, Domain,	Occcurences,	Title,	Link,	Link_Occurences,	Engines) VALUES (?,?, ?, ?, ?, ?, ?)'

    # # Execute the insert command
    # cursor.executemany(insert_sql, results_list)
    # db.commit()

    return results, csv_data

def format_copyscape_output(data):
    output = {}
    for article in data:
        parsed_url = urlparse(article["url"])
        domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if domain not in output:
            output[domain] = {"count": 0, "links": [],
                              "concern": False, "source": []}
        output[domain]["count"] += 1
        output[domain]["links"].append({
            "link": article["url"],
            "title": article["title"],
            "snippet": article["textsnippet"],
            "count": 1,  # Assuming each link is unique and counts as 1
            # Placeholder, as the engine is not specified in the data
            "engines": ["Plagiarism Checker"]
        })
    return output

def format_gdelt_output(data):
    output = {}
    for article in data.get("articles", []):
        parsed_url = urlparse(article["url"])
        domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if domain not in output:
            output[domain] = {"count": 0, "links": [],
                              "concern": False, "source": []}
        output[domain]["count"] += 1
        output[domain]["links"].append({
            "link": article["url"],
            "title": article["title"],
            "snippet": "",
            "count": 1,  # Assuming each link is unique and counts as 1
            # Placeholder, as the engine is not specified in the data
            "engines": ["GDELT"]
        })
    return output

def fetch_serp_results(title_query, content_query, combineOperator, language, country, engines=['google', 'google_news', 'bing', 'bing_news', 'duckduckgo', 'yahoo', 'yandex', 'gdelt', 'copyscape']):
    local_domains = load_domains_of_concern()
    github_domains = fetch_domains_from_github(
        'https://raw.githubusercontent.com/ASD-at-GMF/state-media-profiles/main/State_Media_Matrix.csv')
    paramsList = customize_params_by_platform(title_query, content_query, combineOperator, language, country)
    all_results = []
    aggregated_results = {}
    
    def fetch_results_for_engine(engine):
        nonlocal title_query, content_query, combineOperator, language, country, aggregated_results
        if engine == 'gdelt':
            return fetch_gdelt_results(title_query, content_query, combineOperator, language, country)
        elif engine == 'copyscape' and COPYSCAPE_API_KEY and COPYSCAPE_USER:
            return fetch_copyscape_results(title_query, content_query, combineOperator, language, country)
        else:
            params = paramsList[engine]
            print(params)
            app.logger.info(f"Searching SERP with params: {params}")
            base_url = "https://serpapi.com/search"
            response = requests.get(base_url, params=params)
            return response.json()
    
    def normalize_results(results, engine):
        normalized_data = []
        if engine != 'copyscape' and engine != 'gdelt':
            results = results.get("organic_results", [])
        else:
            if results is None:
                return []
        for result in results:
            if engine == 'copyscape':
                parsed_url = urlparse(result['url'])
                domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                normalized_data.append({'domain':domain, 'url': result['url'], 'title': result['title'], 'snippet': result['textsnippet'],  'engine': engine})
            elif engine == 'gdelt':
                parsed_url = urlparse(result['url'])
                domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                normalized_data.append({'domain':domain, 'url': result['url'], 'title': result['title'], 'snippet': '',  'engine': engine})
            else:
                parsed_url = urlparse(result['link'])
                domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                normalized_data.append({'domain':domain,'url': result.get('link'), 'title': result.get(
                'title'), 'snippet': result.get('snippet') , 'engine': [engine]})
        return normalized_data

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit tasks to the executor for each engine
        future_to_engine = {executor.submit(fetch_results_for_engine, engine): engine for engine in engines}
        
        for future in concurrent.futures.as_completed(future_to_engine):
            engine = future_to_engine[future]
            try:
                data = future.result()
                if data is not None:
                    normalized_data = normalize_results(data, engine)
                    all_results.extend(normalized_data)
                print(f"Results for {engine}: {data}")
            except Exception as exc:
                print(f"{engine} generated an exception: {exc}")
                continue

    # Aggregate by domain, link, title, and count
    local_domains_dict = {domain: source for domain, source in local_domains}
    # Temporary dictionary to hold the first occurrence index of each URL

    url_indexes = {}
    for idx in range(len(all_results) - 1, -1, -1):
        result = all_results[idx]
        url = result['url']
        if url in url_indexes:
        # This URL has been seen before; merge information and delete this occurrence
            first_occurrence_idx = url_indexes[url]
            all_results[first_occurrence_idx]['engines'].extend(result['engine'])
            all_results[first_occurrence_idx]['link_count'] += 1
            all_results[first_occurrence_idx]['score'] = max(
                sequence_match_score(all_results[first_occurrence_idx]['title'], result['title']),
                sequence_match_score(all_results[first_occurrence_idx]['snippet'], result['snippet'])
            )
            all_results.pop(idx)
        else:
            url_indexes[url] = idx
            local_source = local_domains_dict.get(result['domain']) or local_domains_dict.get(result['domain'].split('.')[1])  # Check for FQDN and no subdomain
            github_source = "statemedia" if urlparse(result['domain']).netloc.strip() in github_domains else None
            if local_source is not None:
                #aggregated_results["source"].append(local_source)
                all_results[idx]['source'] = [local_source]
            if github_source is not None:
                #aggregated_results["source"].append(github_source)
                all_results[idx]['source'] = [github_source]
            all_results[idx]['link_count'] = 1
            all_results[idx]['domain_count'] = 1
            all_results[idx]['engines'] = result['engine'] 
            all_results[idx]['score'] = max(sequence_match_score(title_query, all_results[idx]['title']), sequence_match_score(content_query, all_results[idx]['snippet']))
            
            
    # Assuming flattened_data is your list of dictionaries
    all_results = sorted(all_results, key=lambda x: x['score'], reverse=True)

    return all_results


def customize_params_by_platform(title_query, content_query, combineOperator, language, country):
    lang_yandex = language
    lang_yahoo = language
    country_yahoo = country
    country_language = country + "-" + language
    language_country = language + "-" + country
    try:
        location = COUNTRIES[country]
    except:
        location = 'United States'
    try:
        google_domain = DOMAINS_GOOGLE[location]
    except:
        google_domain = 'google.com'

    if language not in LANGUAGES_YANDEX:
        lang_yandex = 'en'  # Default to English
    if language not in LANGUAGES_YAHOO:
        lang_yahoo = 'en'
    if country not in COUNTRIES_YAHOO:
        country_yahoo = 'us'
    if country_language not in COUNTRY_LANGUAGE_DUCKDUCKGO:
        country_language = 'wt-wt'

    paramsList = {
        "google": {
            "engine": "google",
            "location": location,
            "hl": language,
            "gl": country,
            "google_domain": google_domain,
            "num": 40,
            "api_key": SERP_API_KEY
        }, 
        "google_news":{
            "engine": "google",
            "location": location,
            "hl": language,
            "gl": country,
            "google_domain": google_domain,
            "num": 40,
            "tbm": "nws",
            "api_key": SERP_API_KEY
        }, 
        "bing":{
            "engine": "bing",
            "location": location,
            "mkt": language_country,
            "count": 40,
            "api_key":  SERP_API_KEY
        }, 
        "bing_news":{
            "engine": "bing_news",
            "mkt": language_country,
            "location": location,
            "count": 40,
            "api_key":  SERP_API_KEY
        }, 
        "duckduckgo":{
            "engine": "duckduckgo",
            "kl": country_language,
            "api_key":  SERP_API_KEY
        }, 
        "yahoo":{
            "engine": "yahoo",
            "api_key":  SERP_API_KEY,
            "vs": country_yahoo,
            "vl": "lang_" + lang_yahoo,
        }, 
        "yandex":{
            "engine": "yandex",
            "api_key":  SERP_API_KEY,
            "lang": lang_yandex,
            "lr": 84
        }
    }

    for key, params in paramsList.items():
        platform = params['engine']
        base_query = ''
        if platform == 'google' or platform == 'duckduckgo':
            if title_query:
                base_query += "intitle:\"" + title_query + "\""

            if content_query:
                if base_query:
                    base_query += " " + combineOperator + " "  # Combining title and content queries
                base_query += "intext:\"" + content_query + "\""
            paramsList[key]['q'] = base_query
        if platform == 'bing' or platform == 'bing_news':
            if title_query:
                base_query += "intitle:\"" + title_query + "\""

            if content_query:
                if base_query:
                    base_query += " " + combineOperator + " "  # Combining title and content queries
                base_query += "inbody:\"" + content_query + "\""
            paramsList[key]['q'] = base_query

        if platform == 'yandex' or platform == 'yahoo':
            if title_query:
                base_query += "\"" + title_query + "\""

            if content_query:
                if base_query:
                    base_query += " " + combineOperator + " "  # Combining title and content queries
                base_query += "\"" + content_query + "\""
            if platform == 'yandex':
                paramsList[key]['text'] = base_query
            if platform == 'yahoo':
                paramsList[key]['p'] = base_query

    return paramsList


def convert_results_to_csv(results):
    csv_list = []

    # Header
    csv_list.append(','.join(
        ['Domain', 'Domain Occurrences', 'Title', 'Snippet','Link', 'Link Occurrences', 'Engines', 'Score']))

    # Data
    for data in results:
        row = [
            data['domain'],
            str(data['domain_count']),
            data['title'],
            data['snippet'],
            data['url'],
            str(data['link_count']),
            ', '.join(data['engines']),
            str(data['score'])
        ]
        csv_list.append(','.join(row))

    return "\n".join(csv_list)

def truncate_text(text):
    # Replacing each type of quotation mark with an empty string
    if len(text) > 249:
        text = text[:248]
        text = text[:text.rfind(' ')]
    return text

def sequence_match_score(title1, title2):
    """
    Compute the similarity score between two titles using SequenceMatcher.

    Args:
    title1 (str): First title.
    title2 (str): Second title.

    Returns:
    float: Similarity score between the two titles.
    """
    if title1 is None:
        title1 = ""
    if title2 is None:
        title2 = ""
    # Initialize SequenceMatcher with the two titles
    matcher = SequenceMatcher(None, title1, title2)

    # Get the match ratio
    score = matcher.ratio()

    return round(score*100,1)

def summarize_indicators(results, column='indicator_type'):
    try:
        tier_counts = Counter([item.type.split('-')[0] for item in results])
    except AttributeError:
        tier_counts = Counter([item[column].split('-')[0] for item in results])

    # Sort the tier as 1, 2, 3
    tier_counts = {k: v for k, v in sorted(tier_counts.items(), key=lambda item: int(item[0]))}

    # Calculate total count
    total_count = sum(tier_counts.values())

    # Convert counts to percentages
    tier_percentages = {k: (v / total_count) * 100 for k, v in tier_counts.items()}

    return tier_percentages

def load_domains_of_concern(filename=SITES_OF_CONCERN):
    with open(filename, mode="r", encoding="utf-8") as file:
        reader = csv.reader(file)
        next(reader)  # skip header

        return [(urlparse(row[1]).netloc.strip(), row[3].strip()) for row in reader]


def fetch_domains_from_github(url):
    response = requests.get(url)
    response.raise_for_status()
    lines = response.text.splitlines()
    reader = csv.reader(lines)
    next(reader)  # skip header
    # Assuming the URL column is the second column
    return [urlparse(row[4]).netloc.strip() for row in reader]

def url_string_to_valid_urls(url_string):
    urls = url_string.split(",")
    valid_urls = []

    for url in urls:
        url = format_url(url)
        if url is not None:
            valid_urls.append(url)

    return valid_urls

def format_url(url):
    url = url.strip()  # Remove leading/trailing whitespace
    parsed_url = urlparse(url)

    # If the URL lacks both scheme and netloc, attempt to prepend "http://".
    if parsed_url.scheme == "" and parsed_url.netloc == "":
        # This handles cases where the entire URL might be in the path component.
        if parsed_url.path:
            fixed_url = "http://" + url
            parsed_fixed_url = urlparse(fixed_url)
            # If fixing the URL provides a valid netloc, update the URL.
            if parsed_fixed_url.netloc:
                return urlunparse(parsed_fixed_url)
            else:
                # If the fix doesn't yield a valid netloc, return None.
                return None
        else:
            # If there's no path (and thus no domain was found), return None.
            return None
    elif parsed_url.scheme and parsed_url.netloc:
        # The URL is already well-formed; return it as-is.
        return urlunparse(parsed_url)
    else:
        # For other malformed cases, return None.
        return None

def parse_title_content(input_string):
    title_marker = "_title:"
    content_marker = "_content:"

    # Default values if neither title nor content is found
    title = content = input_string

    # Search for the markers in the string
    title_start = input_string.find(title_marker)
    content_start = input_string.find(content_marker)

    if title_start != -1 or content_start != -1:
        # Initialize indices for slicing
        title_end = content_end = len(input_string)

        # Adjust indices if markers are found
        if title_start != -1:
            content_start = input_string.find(content_marker, title_start + len(title_marker))
            title_end = content_start if content_start != -1 else content_end
            title = input_string[title_start + len(title_marker):title_end].strip()
        
        if content_start != -1:
            title_start = input_string.find(title_marker, content_start + len(content_marker))
            content_end = title_start if title_start != -1 else content_end
            content = input_string[content_start + len(content_marker):content_end].strip()

        # Handle cases where only one marker is found
        if title_start == -1: title = input_string
        if content_start == -1: content = input_string

    return title, content


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 8000))  # Default to 8000 if not set
    app.run(host='0.0.0.0', port=port)
