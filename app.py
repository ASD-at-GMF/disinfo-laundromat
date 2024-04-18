from dotenv import load_dotenv
load_dotenv()

from flask import render_template, request, flash, make_response, g,  redirect, url_for, send_file, jsonify, send_from_directory
from flask_bootstrap import Bootstrap
from functools import wraps

import concurrent.futures
import json
import re
from io import BytesIO
import pandas as pd
import requests
from io import StringIO
from urllib.parse import urlparse, urlunparse,unquote
import csv
import sys
from newspaper import Article, Config
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from collections import Counter
import io
import zipfile
import numpy as np
import traceback
import os
import bleach
import logging
from sqlalchemy import insert

# Paramaterizable Variables
SERP_API_KEY = os.getenv('SERP_API_KEY')
SITES_OF_CONCERN = os.getenv('SITES_OF_CONCERN', '')
KNOWN_INDICATORS = os.getenv('KNOWN_INDICATORS', '')
MYIPMS_API_PATH = os.getenv('MYIPMS_API_PATH', '')
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY', '')
COPYSCAPE_API_KEY = os.getenv('COPYSCAPE_API_KEY', '')
COPYSCAPE_USER = os.getenv('COPYSCAPE_USER', '')
PATH_TO_OUTPUT_CSV = os.getenv('PATH_TO_OUTPUT_CSV', '')
MATCH_VALUES_TO_IGNORE = os.getenv('MATCH_VALUES_TO_IGNORE', '')
CURRENT_ENVIRONMENT = os.getenv('CURRENT_ENVIRONMENT', 'production')
CAPTCHA_SECRET = os.getenv('CAPTCHA_SECRET', '')

from init_app import db, init_app
from models import RegistrationKey, SiteBase, SiteIndicator, User
from modules.reference import DEFAULTS, ENGINES, LANGUAGES, COUNTRIES, LANGUAGES_YANDEX, LANGUAGES_YAHOO, COUNTRIES_YAHOO, COUNTRY_LANGUAGE_DUCKDUCKGO, DOMAINS_GOOGLE, INDICATOR_METADATA, MATCH_VALUES_TO_IGNORE
# Import all your functions here
from modules.crawler import crawl_one_or_more_urls, annotate_indicators
from modules.matcher import find_matches
from modules.email_utils import send_results_email

app = init_app(os.getenv("CONFIG_MODE"))
Bootstrap(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(filename='debug.log',
                        level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s'
                        )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def insert_sites_of_concern(local_domains):
    app.logger.info("Inserting indicators: %s", local_domains)
    # Check if the table is empty.
    engine = db.session.get_bind()
    with engine.connect() as conn:
        if SiteBase.query.first() is None:
            conn.execute(
                insert(SiteBase),
                [{"domain": domain, "source": source} for domain, source in local_domains]
            )
            conn.commit()


def insert_indicators(indicators):
    app.logger.info("Inserting indicators: %s", indicators)
    engine = db.session.get_bind()
    with engine.connect() as conn:
        conn.execute(
            insert(SiteIndicator),
            [{"domain": indicator['domain_name'],
            "indicator_type": indicator['indicator_type'],
            "indicator_tier": indicator['indicator_tier'],
            "indicator_content": str(indicator['indicator_content'])}
            for indicator in indicators]
        )
        conn.commit()

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

    user = User.query.filter_by(username = username).first()


    if reg_key is not None and user is None:
        reg_key_db = db.session.get(RegistrationKey, reg_key)
        if reg_key_db is not None:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            login_user(user)
            is_logged_in = True
        
    elif user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
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

    reg_key = db.session.get(RegistrationKey, reg_key)
    if reg_key:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        login_user(user)
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

def verify_captcha(request):
    # if recaptcha is in the form, verify it
    if 'recaptcha_response' in request.form:
        recaptcha_response = request.form['recaptcha_response']

        params = {
            'secret': CAPTCHA_SECRET,
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=params)
        result = response.json()
        if result['success'] and result['score'] >= 0.5:  # You can adjust the score threshold
            return True
        else:
            return False
    return True

@app.route('/url-search', methods=['GET','POST'])
@clean_inputs
def url_search():
    try:
        if request.method == 'POST':
            #verify captcha
            if not verify_captcha(request):
                return render_template('index.html', error_message="Silent captcha verification failed. Try again or contact info [at] securingdemocracy.org. Please do not use automated tools to interact with this form.", engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)
        indicators_df, matches_df, indicator_summary, matches_summary = fingerprint(request)
        return render_template('index.html', engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA, indicators_df=indicators_df.to_dict('records'), matches_df=matches_df.to_dict('records'), indicator_summary = indicator_summary, matches_summary = matches_summary)
    except Exception as e:
        return render_template('error.html', errorx=e, errortrace=traceback.format_exc())


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
    if request.method == 'POST':
        url = request.form['url']
        run_urlscan =  request.form['run_urlscan']  if 'run_urlscan' in request.form else False
        internal_only =  request.form['internal_only']  if 'internal_only' in request.form else False 
    elif request.method == 'GET':
        url = request.args.get('url')
        run_urlscan =  request.args['run_urlscan']  if 'run_urlscan' in request.args else False
        internal_only =  request.args['internal_only']  if 'internal_only' in request.args else False 
    # Validation checks for internal_only and run_urlscan
    internal_only = bool(internal_only)
    run_urlscan = bool(run_urlscan)


    urls = url_string_to_valid_urls(url)
    return find_indicators_and_matches(urls, run_urlscan = run_urlscan, internal_only = internal_only)

def find_indicators_and_matches(urls, run_urlscan = False, internal_only = False):
    indicators = crawl_one_or_more_urls(urls, run_urlscan = run_urlscan)
    indicator_summary = summarize_indicators(indicators)
    indicators_df = pd.DataFrame([o.__dict__ for o in indicators])
    indicators_df = indicators_df.rename(columns={'content': 'indicator_content', 'domain': 'domain_name', 'type': 'indicator_type', 'tier': 'indicator_tier'})
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
    matches_summary = summarize_indicators(matches_df.to_dict('records'))

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
    if request.method == 'GET' and len(request.args) > 0:
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

@app.route('/content-search', methods=['GET','POST'])
@app.route('/api/content-search', methods=['POST'])
@clean_inputs
def parse_content_search():
    if request.method == 'POST':
        contentToSearch = request.form.get('contentToSearch')
        isApi = request.form.get('isApi', 'false')
        if not verify_captcha(request):
            return render_template('index.html', error_message="Silent captcha verification failed. Try again or contact info [at] securingdemocracy.org. Please do not use automated tools to interact with this form.", engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

    if request.method == 'GET':
        contentToSearch = request.args.get('contentToSearch')
        isApi = request.args.get('isApi', 'false')
    # Parse the URL
    parsed_url = format_url(contentToSearch)

    if parsed_url is not None: 
        try:
            results, csv_data = parse_url(request, contentToSearch)
        except Exception as e:
            error_message = f"This URL could not automatically be parsed: {parsed_url} ; Manually enter a title and/or content query."
            return render_template('index.html', error_message = error_message, engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)
    else:
        title_query, content_query = parse_title_content(contentToSearch)
        results, csv_data = content(request, title_query, content_query)
    if isApi == 'true':
        return jsonify({'results': results, 'csv_data': csv_data, 'countries': COUNTRIES, 'languages': LANGUAGES, 'indicator_metadata': INDICATOR_METADATA})
    else:
        return render_template('index.html', request=request, results=results, csv_data=csv_data, engines=ENGINES, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

def content(request, title_query=None, content_query=None):
    if request.method == 'POST':
        title_query = title_query if title_query is not None else  request.form.get('titleQuery')
        content_query = content_query if content_query is not None else request.form.get('contentQuery')
        combineOperator = request.form.get('combineOperator', 'OR')
        language = request.form.get('language', 'en') 
        country = request.form.get('country', 'us') 
        engines = request.form.getlist('search_engines')
    elif request.method == 'GET':
        title_query = title_query if title_query is not None else unquote(request.args.get('titleQuery'))
        content_query = content_query if content_query is not None else unquote(request.args.get('contentQuery'))
        combineOperator = request.args.get('combineOperator', 'OR')
        language = request.args.get('language', 'en')
        country = request.args.get('country', 'us')
        engines = request.args.getlist('search_engines', ['all'] )

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

@app.route('/api/parse-url', methods=['POST'])
@clean_inputs
def parse_url_api():
    try:
        results, csv_data = parse_url(request)
        return jsonify({'results': results, 'csv_data': csv_data, 'countries': COUNTRIES, 'languages': LANGUAGES, 'indicator_metadata': INDICATOR_METADATA})
    
    except Exception as e:
        return jsonify({'error': "This page could not automatically be parsed for content. Please enter a title and/or content query manually."})
        
def parse_url(request, urlToParse=None):
    if request.method == 'POST':
        url = urlToParse if urlToParse is not None else request.form.get('url', '')
        url = format_url(url)
        engines = request.form.getlist('search_engines')
        combineOperator = request.form.get('combineOperator', 'OR')
        language = request.form.get('language', 'en')
        country = request.form.get('country', 'us')
    elif request.method == 'GET':
        url = urlToParse if urlToParse is not None else request.args.get('url', '')
        url = format_url(url)
        engines = request.args.getlist('search_engines')
        combineOperator = request.args.get('combineOperator', 'OR')
        language = request.args.get('language', 'en')
        country = request.args.get('country', 'us')

    if  engines == 'all' or engines == ['all'] or engines == []:
        engines = ['google', 'google_news', 'bing', 'bing_news', 'duckduckgo', 'yahoo', 'yandex', 'gdelt', 'copyscape']
    if isinstance(engines, str):
        engines = [engines]
    if any(isinstance(sublist, list) for sublist in engines):
        engines = [item for sublist in engines for item in sublist]
    if combineOperator == 'False' or combineOperator == 'false':
        combineOperator = 'OR'
    elif combineOperator == 'True' or combineOperator == 'true':
        combineOperator = 'AND'

        
    article = Article(url)
    article.download()
    article.parse()

    return fetch_content_results(
            article.title, article.text, combineOperator, language, country, engines=engines)


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
            searched_url = row.get("url") or row.get("\ufeffurl")
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
    output = []
    for article in data:
        output.append({
            "url": article["url"],
            "title": article["title"],
            "snippet": article["textsnippet"],
        })
    return output

def format_gdelt_output(data):
    output = []
    for article in data.get("articles", []):
        output.append({
            "url": article["url"],
            "title": article["title"],
            "snippet": "",
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
            if engine == 'copyscape' or engine == 'gdelt':
                parsed_url = urlparse(result['url'])
                domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                normalized_data.append({'domain':domain, 'url': result['url'], 'title': result['title'], 'snippet': result['snippet'],  'engine': [engine]})
            else:
                parsed_url = urlparse(result['link'])
                domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                normalized_data.append({'domain':domain,'url': result.get('link'), 'title': result.get('title'), 'snippet': result.get('snippet') , 'engine': [engine]})
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
    aggregated_results = []
    try:
        for idx in range(len(all_results) - 1):
            
            result = all_results[idx]
            url = result['url']
            if url in url_indexes:
            # This URL has been seen before; merge information and delete this occurrence
                try:
                    first_occurrence_idx = url_indexes[url]
                    aggregated_results[first_occurrence_idx]['engines'].extend(result['engine'])
                    aggregated_results[first_occurrence_idx]['link_count'] += 1
                    aggregated_results[first_occurrence_idx]['score'] = max(
                        aggregated_results[first_occurrence_idx]['score'],
                        max(
                            sequence_match_score(title_query, result['title']),
                            sequence_match_score(content_query, result['snippet']) if result['snippet'] != ''  else 0
                        )
                    )
                    if sequence_match_score(result['title'], title_query) > sequence_match_score(aggregated_results[first_occurrence_idx]['title'], title_query):
                        aggregated_results[first_occurrence_idx]['title'] = result['title']
                    if sequence_match_score(result['snippet'], content_query) > sequence_match_score(aggregated_results[first_occurrence_idx]['snippet'], content_query):
                        aggregated_results[first_occurrence_idx]['snippet'] = result['snippet']
                except Exception as e:
                    print(f"Error merging results: {e}")
                    continue
            else:
                aggregated_results.append(all_results[idx])
                agg_idx = len(aggregated_results) - 1
                url_indexes[url] = agg_idx
                local_source = local_domains_dict.get(urlparse(result['domain']).netloc.strip()) or local_domains_dict.get(urlparse(result['domain']).netloc.strip().split('.')[1])  # Check for FQDN and no subdomain
                github_source = "statemedia" if urlparse(result['domain']).netloc.strip() in github_domains else None
                aggregated_results[agg_idx]['source'] = []
                if local_source is not None:
                    aggregated_results[agg_idx]['source'] = local_source
                if github_source is not None:
                    aggregated_results[agg_idx]['source'] = github_source
                aggregated_results[agg_idx]['link_count'] = 1
                aggregated_results[agg_idx]['domain_count'] = 1
                aggregated_results[agg_idx]['engines'] = result['engine'] 
                aggregated_results[agg_idx]['score'] = max(sequence_match_score(title_query, result['title']), sequence_match_score(content_query, result['snippet']) if result['snippet'] != ''  else 0)
    except Exception as e:
        print(f"Error aggregating results: {e}")
        app.logger.error(f"Error aggregating results: {e}")            
    # convet list of engines to set to delete duplicates
    for result in aggregated_results:
        result['engines'] = list(set(result['engines']))

    # Assuming flattened_data is your list of dictionaries
    aggregated_results = sorted(aggregated_results, key=lambda x: x['score'], reverse=True)

    return aggregated_results


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

def summarize_indicators(results, tier_column='indicator_tier'):
    try:
        tier_counts = Counter([item.tier for item in results])
    except AttributeError:
        tier_counts = Counter([item[tier_column] for item in results])

    # Sort the tier as 1, 2, 3
    tier_counts = {k: v for k, v in sorted(tier_counts.items())}

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

    # If the URL lacks a domain, return None.
    if '.' not in url or ' ' in url:
        return None
    # If the URL lacks both scheme and netloc, attempt to prepend "http://".
    elif parsed_url.scheme == "" and parsed_url.netloc == "":
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
    with app.app_context():
        db.create_all()
        insert_sites_of_concern(load_domains_of_concern())
    port = int(os.getenv("PORT", 8000))  # Default to 8000 if not set
    app.run(host='0.0.0.0', port=port)
