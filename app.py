
from flask import Flask, render_template, request, flash, make_response, g,  redirect, url_for, send_file
from flask_bootstrap import Bootstrap
import json
import re
from io import BytesIO
import pandas as pd
import requests
from io import StringIO
from urllib.parse import urlparse
import csv
import sys
from newspaper import Article
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

# Paramaterizable Variables
from config import SERP_API_KEY, SITES_OF_CONCERN, KNOWN_INDICATORS, APP_SECRET_KEY, SQLLITE_DB_PATH,  COPYSCAPE_API_KEY, COPYSCAPE_USER, PATH_TO_OUTPUT_CSV, MATCH_VALUES_TO_IGNORE
from modules.reference import LANGUAGES, COUNTRIES, LANGUAGES_YANDEX, LANGUAGES_YAHOO, COUNTRIES_YAHOO, COUNTRY_LANGUAGE_DUCKDUCKGO, DOMAINS_GOOGLE, INDICATOR_METADATA
# Import all your functions here
from modules.crawler import crawl_one_or_more_urls
from modules.matcher import find_matches
from modules.email import send_results_email

app = Flask(__name__)
bootstrap = Bootstrap(app)
bcrypt = Bcrypt(app)
app.secret_key = APP_SECRET_KEY  # Set a secret key for security purposes

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    # Check if the table is empty
    if db.execute('SELECT COUNT(*) FROM sites_base').fetchone()[0] == 0:
        # If empty, insert the local_domains
        db.executemany('INSERT INTO sites_base (domain, source) VALUES (?, ?)',
                       [(domain, source) for domain, source in local_domains])
        db.commit()


def insert_indicators(indicators):
    db = get_db()

    # If empty, insert the local_domains
    db.executemany('INSERT INTO site_fingerprint (domain_name, indicator_type, indicator_content) VALUES (?, ?, ?)',
                   [(indicator['domain_name'], indicator['indicator_type'], str(indicator['indicator_content'])) for indicator in indicators])
    db.commit()

#### ROUTES ####


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password'], password):
            user_obj = User(
                id=user['id'], username=user['username'], password=user['password'])
            login_user(user_obj)
            return redirect(url_for('index'))
        return 'Invalid username or password'

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out'


@app.route('/fingerprint', methods=['GET', 'POST'])
@login_required
def fingerprint():
    url = ''
    if request.method == 'POST':
        url = request.form['url']
        run_urlscan =  'run_urlscan' in request.form
        internal_only = 'internal_only' in request.form
        # Do something with the url using your functions
        try:
            urls = url.split(',')
            
            indicators_df, matches_df, indicator_summary, matches_summary = find_indicators_and_matches(urls, run_urlscan = run_urlscan, internal_only = internal_only)

            return render_template('index.html', url=url, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA, indicators_df=indicators_df.to_dict('records'), matches_df=matches_df.to_dict('records'), indicator_summary = indicator_summary, matches_summary = matches_summary)

        except Exception as e:
            return render_template('error.html', errorx=e, errortrace=traceback.format_exc())

    return render_template('index.html', countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)


def find_indicators_and_matches(urls, run_urlscan = False, internal_only = False):
    indicators = crawl_one_or_more_urls(urls, run_urlscan = run_urlscan)
    indicator_summary = summarize_indicators(indicators)
    indicators_df = pd.DataFrame(
        columns=["indicator_type", "indicator_content", "domain_name"],
        data=indicators,
    )
    filter_mask = ~indicators_df['indicator_content'].isin(MATCH_VALUES_TO_IGNORE)
    indicators_df = indicators_df[filter_mask]

    insert_indicators(indicators)

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
    matches_summary = summarize_indicators(matches_df.to_dict('records'), column='match_type')

    return indicators_df, matches_df, indicator_summary, matches_summary

@app.route('/content', methods=['GET', 'POST'])
def content():
    results = None
    csv_data = None

    if request.method == 'POST':
        title_query = request.form.get('titleQuery')
        content_query = request.form.get('contentQuery')
        combineOperator = request.form.get('combineOperator')
        language = request.form.get('language')
        country = request.form.get('country')
        engines = request.form.getlist('search_engines')

        if engines == ['all'] or engines == []:
            engines = ['google', 'google_news', 'bing', 'bing_news', 'duckduckgo', 'yahoo', 'yandex', 'gdelt', 'copyscape']

        if not title_query and not content_query:
            # Error message if neither is provided
            flash("Please provide at least a title or content query.")
        else:
            results, csv_data = fetch_content_results(
                title_query, content_query, combineOperator, language, country, engines=engines)

    return render_template('index.html', results=results, csv_data=csv_data, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)


@app.route('/parse-url', methods=['POST'])
def parse_url():
    url = request.form['url']
    engines = request.form.getlist('search_engines')

    if engines == ['all'] or engines == []:
        engines = ['google', 'google_news', 'bing', 'bing_news', 'duckduckgo', 'yahoo', 'yandex', 'gdelt', 'copyscape']

    if not url:
        return render_template('index.html', countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)
    try:
        # Extracting article data-
        article = Article(url)
        article.download()
        article.parse()

        results, csv_data = fetch_content_results(
                article.title, article.text, "OR", "en", "us", engines=engines)

        return render_template('index.html', results=results, csv_data=csv_data, countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

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
        
        return render_template('index.html', countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

@app.route('/content-csv', methods=['POST'])
def upload_file():
    file = request.files['file']
    email_recipient = request.form.get('email')
    if file:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline='')
        csv_input = csv.DictReader(stream)

        # Prepare to write to a new CSV file
        output_stream = io.StringIO()
        csv_output = csv.writer(output_stream)
        csv_output.writerow(['SearchedURL', 'Domain', 'Source', 'URL', 'Title', 'Snippet', 'LinkCount', 'Engines', 'DomainCount', 'Score'])

        results_df = pd.DataFrame(columns=['SearchedURL', 'Domain', 'Source', 'URL', 'Title', 'Snippet', 'LinkCount', 'Engines', 'DomainCount', 'Score'])
        # Process each URL in the CSV
        for row in csv_input:
            searched_url = row.get("Urls")
            try:
                # if  'title' in row and 'content' in row:
                #     title_query = row['title']
                #     content_query = row['content']

                #     #todo: add language and country from csv

                #     results, csv_data = fetch_content_results(
                #         title_query, content_query, "OR", "en","us", engines=['google', 'google_news', 'bing', 'bing_news', 'yahoo', 'yandex'])

                if searched_url:
                    
                    article = Article(searched_url)
                    article.download()
                    article.parse()

                    #todo: add language and country from csv
                    results, csv_data = fetch_content_results(
                        article.title, article.text, "OR", "en","us", engines=['google', 'bing',  'yandex'])
                # Initialize an empty list to hold all the new rows
                all_new_rows = []

                # Loop through the results and create a list of new rows
                for result in results:
                    new_row = [searched_url,

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
                print(f"Error processing {searched_url}: {e}, continuing...")
                        # Reset file pointer to the beginning
                results_df.to_csv('out_partial.csv', index=False)

                continue

        # Reset file pointer to the beginning
        results_df.to_csv(PATH_TO_OUTPUT_CSV, index=False)
        try:
            send_results_email(
             email_recipient, "Disinfo Laundromat Results", "Please find the results from the Disinfo Laundromat analysis attached. ", PATH_TO_OUTPUT_CSV)
        except Exception as e:
            print(f"Error sending email: {e}, continuing...")
        finally:
            return send_file( PATH_TO_OUTPUT_CSV, as_attachment=True)

@app.route('/fingerprint-csv', methods=['POST'])
def fingerprint_file():
    file = request.files['fingerprint-file']
    internal_only = 'internal_only' in request.form
    if file:    
        df_urls = pd.read_csv(StringIO(file.read().decode('utf-8')))
        urls = df_urls['Urls'].tolist()  # Assuming 'Urls' is the column name

        # The find_indicators_and_matches function should be defined elsewhere
        indicators_df, matches_df, indicator_summary, matches_summary = find_indicators_and_matches(urls, internal_only = internal_only)

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

        print('Zipped - downloading...')
        # Prepare the zip file to send to client
        mem_zip.seek(0)
        return send_file(
            mem_zip,
            mimetype='application/zip',
            as_attachment=True,
            download_name='indicators_and_matches.zip'
        )

    # If no file, render the index template
    return render_template('index.html', countries=COUNTRIES, languages=LANGUAGES, indicator_metadata=INDICATOR_METADATA)

@app.route('/download_csv', methods=['POST'])
def download_csv():
    csv_data = request.form.get('csv_data', '')

    output = make_response(csv_data)
    output.headers["Content-Disposition"] = "attachment; filename=results.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/indicators')
def indicators():
    # Get the selected type from the query parameters
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

    return render_template('indicators.html', data=data, unique_types=unique_types, selected_type=selected_type, indicator_metadata=INDICATOR_METADATA)


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
        print(f"Error during request: {e}")
        return None


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
        domain = urlparse(article["url"]).netloc
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
        domain = urlparse(article["url"]).netloc
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
    results_gdelt = None
    if 'gdelt' in engines:
        results_gdelt = fetch_gdelt_results(
            title_query, content_query, combineOperator, language, country)
    results_cs = None
    if COPYSCAPE_API_KEY and COPYSCAPE_USER and 'copyscape' in engines:
        results_cs = fetch_copyscape_results(
            title_query, content_query, combineOperator, language, country)

    paramsList = customize_params_by_platform(
        title_query, content_query, combineOperator, language, country)
    aggregated_results = {}
    for params in paramsList:
        search_engine = params["engine"]
        if search_engine not in engines:
            continue

        base_url = "https://serpapi.com/search"  # base url of the API
        response = requests.get(base_url, params=params)
        data = response.json()
        organic_results = data.get("organic_results", [])
        print(params)

        # Aggregate by domain, link, title, and count occurrences
        for result in organic_results:
            domain = urlparse(result.get('link')).netloc
            link_data = {'link': result.get('link'), 'title': result.get(
                'title'), 'snippet': result.get('snippet') , 'count': 1, 'engines': [search_engine]}

            if domain not in aggregated_results:
                aggregated_results[domain] = {'count': 0, 'links': []}

            # Check if the link already exists in the list
            existing_link = next(
                (l for l in aggregated_results[domain]['links'] if l['link'] == link_data['link']), None)
            if existing_link:
                existing_link['count'] += 1
                if search_engine not in existing_link['engines']:
                    existing_link['engines'].append(search_engine)
            else:
                aggregated_results[domain]['links'].append(link_data)

            aggregated_results[domain]['count'] += 1
    if results_gdelt and results_gdelt is not None:
        for key, value in results_gdelt.items():
            if key in aggregated_results:
                # Sum the 'count' for overlapping keys
                aggregated_results[key]['count'] += value['count']
                combined_links = aggregated_results[key]['links'] + value['links']
                aggregated_results[key]['links'] = combined_links
            else:
                # If the key is not in the first dictionary, add it
                aggregated_results[key] = value

    if COPYSCAPE_API_KEY and COPYSCAPE_USER and results_cs and results_cs is not None:
        for key, value in results_cs.items():
            if key in aggregated_results:
                # Sum the 'count' for overlapping keys
                aggregated_results[key]['count'] += value['count']
                combined_links = aggregated_results[key]['links'] + value['links']
                aggregated_results[key]['links'] = combined_links
            else:
                # If the key is not in the first dictionary, add it
                aggregated_results[key] = value

    local_domains_dict = {domain: source for domain, source in local_domains}
    # Flagging domains of concern and tracking their source
    for domain, data in aggregated_results.items():
        local_source = local_domains_dict.get(domain) or local_domains_dict.get(domain.split('.')[1])  # Check for FQDN and no subdomain
        github_source = "statemedia" if domain in github_domains else None

        print(domain, local_source, github_source)
        # Set concern flag and sources
        data["concern"] = bool(local_source or github_source)
        data["source"] = []

        if local_source:
            data["source"].append(local_source)
        if github_source:
            data["source"].append(github_source)

    aggregated_results = dict(sorted(aggregated_results.items(
    ), key=lambda item: item[1]['count'], reverse=True))

    # FLATTEN DOMAINS Iterate over each domain in the JSON data

    flattened_data = []

    for domain, domain_data in aggregated_results.items():
        for link in domain_data['links']:
            # Create a dictionary for each link with the required information
            link_info = {
                'domain': domain,
                'source': domain_data['source'],
                'url': link['link'],
                'title': link['title'],
                'snippet': link['snippet'],
                'link_count': link['count'],
                'engines': link['engines'],
                'domain_count': domain_data['count'],
                'score' : max(sequence_match_score(title_query, link['title']), sequence_match_score(content_query, link['snippet']))
            }
            # Add the dictionary to the list
            flattened_data.append(link_info)

    # Assuming flattened_data is your list of dictionaries
    flattened_data = sorted(flattened_data, key=lambda x: x['score'], reverse=True)


    return flattened_data


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

    paramsList = [
        {
            "engine": "google",
            "location": location,
            "hl": language,
            "gl": country,
            "google_domain": google_domain,
            "num": 40,
            "api_key": SERP_API_KEY
        }, {
            "engine": "google",
            "location": location,
            "hl": language,
            "gl": country,
            "google_domain": google_domain,
            "num": 40,
            "tbm": "nws",
            "api_key": SERP_API_KEY
        }, {
            "engine": "bing",
            "location": location,
            "mkt": language_country,
            "count": 40,
            "api_key":  SERP_API_KEY
        }, {
            "engine": "bing_news",
            "mkt": language_country,
            "location": location,
            "count": 40,
            "api_key":  SERP_API_KEY
        }, {
            "engine": "duckduckgo",
            "kl": country_language,
            "api_key":  SERP_API_KEY
        }, {
            "engine": "yahoo",
            "api_key":  SERP_API_KEY,
            "vs": country_yahoo,
            "vl": "lang_" + lang_yahoo,
        }, {
            "engine": "yandex",
            "api_key":  SERP_API_KEY,
            "lang": lang_yandex,
            "lr": 84
        }
    ]

    for idx, params in enumerate(paramsList):
        platform = params['engine']
        base_query = ''
        if platform == 'google' or platform == 'duckduckgo':
            if title_query:
                base_query += "intitle:\"" + title_query + "\""

            if content_query:
                if base_query:
                    base_query += " " + combineOperator + " "  # Combining title and content queries
                base_query += "intext:\"" + content_query + "\""
            paramsList[idx]['q'] = base_query
        if platform == 'bing' or platform == 'bing_news':
            if title_query:
                base_query += "intitle:\"" + title_query + "\""

            if content_query:
                if base_query:
                    base_query += " " + combineOperator + " "  # Combining title and content queries
                base_query += "inbody:\"" + content_query + "\""
            paramsList[idx]['q'] = base_query

        if platform == 'yandex' or platform == 'yahoo':
            if title_query:
                base_query += "\"" + title_query + "\""

            if content_query:
                if base_query:
                    base_query += " " + combineOperator + " "  # Combining title and content queries
                base_query += "\"" + content_query + "\""
            if platform == 'yandex':
                paramsList[idx]['text'] = base_query
            if platform == 'yahoo':
                paramsList[idx]['p'] = base_query

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
    # Initialize SequenceMatcher with the two titles
    matcher = SequenceMatcher(None, title1, title2)

    # Get the match ratio
    score = matcher.ratio()

    return round(score*100,1)

def summarize_indicators(results, column='indicator_type'):
    """
    Generate a summary of results with the number of occurrences for each tier.

    Args:
    results (list of dicts): List containing indicator data.

    Returns:
    str: A formatted summary string.
    """
    summary = []
    tier_counts = Counter([item[column].split('-')[0] for item in results])

    # sort the tier as 1, 2, 3
    tier_counts = {k: v for k, v in sorted(tier_counts.items(), key=lambda item: int(item[0]))}    

    return tier_counts

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


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
 