
from flask import Flask, render_template, request, flash, make_response, g
from flask_bootstrap import Bootstrap
import requests
from io import StringIO
from urllib.parse import urlparse
import csv
import sqlite3

# Paramaterizable Variables
from config import SERP_API_KEY, SITES_OF_CONCERN, KNOWN_INDICATORS
from reference import LANGUAGES, COUNTRIES, LANGUAGES_YANDEX, LANGUAGES_YAHOO, COUNTRIES_YAHOO, COUNTRY_LANGUAGE_DUCKDUCKGO, DOMAINS_GOOGLE
# Import all your functions here
from crawler import *
from matcher import find_matches

app = Flask(__name__)
Bootstrap(app)

DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
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
                       [(domain,source) for domain,source in local_domains])
        db.commit()

def insert_indicators(indicators):
    db = get_db()   

    # If empty, insert the local_domains
    db.executemany('INSERT INTO site_fingerprint (domain_name, indicator_type, indicator_content) VALUES (?, ?, ?)',
                    [(indicator['domain_name'], indicator['indicator_type'], str(indicator['indicator_content'])) for indicator in indicators])
    db.commit()


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', countries=COUNTRIES, languages=LANGUAGES)


@app.route('/fingerprint', methods=['GET', 'POST'])
def fingerprint():
    url = ''
    if request.method == 'POST':
        url = request.form['url']
        # Do something with the url using your functions
        try:
            indicators = crawl(url, set())
            indicators_df = pd.DataFrame(
                columns=["indicator_type", "indicator_content", "domain_name"],
                data=indicators,
            )
            
            insert_indicators(indicators)

            comparison_indicators = pd.read_csv(KNOWN_INDICATORS)  # read the csv file
            #print(indicators_df.head(), comparison_indicators.head())
            # Find matches
            matches_df = find_matches(indicators_df, comparison=comparison_indicators)

            return render_template('index.html', url=url, countries=COUNTRIES, languages=LANGUAGES, indicators_df=indicators_df.to_html(classes='table table-striped'), matches_df=matches_df.to_html(classes='table table-striped'))
 
        except Exception as e:
            return render_template('error.html', error=e)

    return render_template('index.html', countries=COUNTRIES, languages=LANGUAGES)


@app.route('/content', methods=['GET', 'POST'])
def content():
    results = None

    if request.method == 'POST':
        title_query = request.form.get('titleQuery')
        content_query = request.form.get('contentQuery')
        combineOperator = request.form.get('combineOperator')
        language = request.form.get('language')
        country = request.form.get('country')

        if not title_query and not content_query:
            # Error message if neither is provided
            flash("Please provide at least a title or content query.")
        else:
            results = fetch_results(title_query, content_query, combineOperator, language, country)
            # Convert results to CSV
            csv_data = convert_results_to_csv(results)
            # Save the query to the database

            db = get_db()
            cursor = db.cursor()
            cursor.execute('INSERT INTO content_queries (title_query, content_query, combine_operator, language, country) VALUES (?, ?, ?, ?, ?)',
                        (title_query, content_query, combineOperator, language, country))
            db.commit()
            # Get the last inserted row ID
            cq_id = cursor.lastrowid
            
            results_list = []
            for domain, data in results.items():
                for link_data in data['links']:
                    res =  [
                        cq_id,
                        domain,
                        str(data['count']),
                        link_data['title'],
                        link_data['link'],
                        str(link_data['count']),
                        ', '.join(link_data['engines'])
                    ]
                    results_list.append(res)

            # Insert data into the database
            # Prepare your SQL insert statement including the additional column
            insert_sql = 'INSERT INTO content_queries_results (cq_id, Domain,	Occcurences,	Title,	Link,	Link_Occurences,	Engines) VALUES (?,?, ?, ?, ?, ?, ?)'

            # Execute the insert command
            cursor.executemany(insert_sql, results_list)
            db.commit()

    return render_template('index.html', results=results, csv_data=csv_data, countries=COUNTRIES, languages=LANGUAGES)

@app.route('/download_csv', methods=['POST'])
def download_csv():
    csv_data = request.form.get('csv_data', '')

    output = make_response(csv_data)
    output.headers["Content-Disposition"] = "attachment; filename=results.csv"
    output.headers["Content-type"] = "text/csv"
    return output

def filter_gdelt_query(query):
    """
    Remove words of two letters or fewer and non-alphanumeric characters from the query.
    """
    # Remove non-alphanumeric characters
    alphanumeric_query = re.sub(r'\W+', ' ', query)
    # Filter out short words
    return ' '.join(word for word in alphanumeric_query.split() if len(word) > 2)

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
            results_gdelt = format_output(results_gdelt)
        else:
            print("Failed to fetch  GDELT data")
        
        return results_gdelt
    except requests.RequestException as e:
        print(f"Error during request: {e}")
        return None

# TODO Federate this out 
def fetch_results(title_query, content_query, combineOperator, language, country):
     # Parameters for SERPAPI Google integration
    results = fetch_serp_results(title_query, content_query, combineOperator, language, country)

    return results


def format_output(data):
    output = {}
    for article in data.get("articles", []):
        domain = urlparse(article["url"]).netloc
        if domain not in output:
            output[domain] = {"count": 0, "links": [], "concern": False, "source": []}
        output[domain]["count"] += 1
        output[domain]["links"].append({
            "link": article["url"],
            "title": article["title"],
            "count": 1,  # Assuming each link is unique and counts as 1
            "engines": ["GDELT"]  # Placeholder, as the engine is not specified in the data
        })
    return output

def fetch_serp_results(title_query, content_query, combineOperator, language, country):
    local_domains = load_domains_of_concern()
    github_domains = fetch_domains_from_github('https://raw.githubusercontent.com/ASD-at-GMF/state-media-profiles/main/State_Media_Matrix.csv')
    results_gdelt = fetch_gdelt_results(title_query, content_query, combineOperator, language, country)

    paramsList = customize_params_by_platform(title_query, content_query, combineOperator, language, country)                  
    aggregated_results = {}
    for params in paramsList:
        search_engine = params["engine"]
        base_url = "https://serpapi.com/search"  # base url of the API
        response = requests.get(base_url, params=params)
        data = response.json()
        organic_results = data.get("organic_results", [])
        print(params)

        # Aggregate by domain, link, title, and count occurrences
        for result in organic_results:
            domain = urlparse(result.get('link')).netloc
            link_data = {'link': result.get('link'), 'title': result.get('title'), 'count': 1, 'engines': [search_engine]}
            
            if domain not in aggregated_results:
                aggregated_results[domain] = {'count': 0, 'links': []}
            
            # Check if the link already exists in the list
            existing_link = next((l for l in aggregated_results[domain]['links'] if l['link'] == link_data['link']), None)
            if existing_link:
                existing_link['count'] += 1
                if search_engine not in existing_link['engines']:
                    existing_link['engines'].append(search_engine)
            else:
                aggregated_results[domain]['links'].append(link_data)

            aggregated_results[domain]['count'] += 1

    for key, value in results_gdelt.items():
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
        local_source = local_domains_dict.get(domain)
        github_source = "statemedia" if domain in github_domains else None
        
        print(domain, local_source, github_source)
        # Set concern flag and sources
        data["concern"] = bool(local_source or github_source )
        data["source"] = []

        if local_source:
            data["source"].append(local_source)
        if github_source:
            data["source"].append(github_source)

    aggregated_results = dict(sorted(aggregated_results.items(), key=lambda item: item[1]['count'], reverse=True))

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

    paramsList = [
        {
        "engine": "google",
        "location": location,
        "hl": language,
        "gl": country,
        "google_domain": google_domain,
        "num": 40,
        "api_key": SERP_API_KEY
        },{
        "engine": "google",
        "location": location,
        "hl": language,
        "gl": country,
        "google_domain": google_domain,
        "num": 40,
        "tbm":"nws",
        "api_key": SERP_API_KEY
        },{
        "engine": "bing",
        "location": location,
        "mkt": language_country,
        "count": 40,
        "api_key":  SERP_API_KEY
        },{
        "engine": "bing_news",
        "mkt": language_country,
        "location": location,
        "count": 40,
        "api_key":  SERP_API_KEY
        },{
        "engine": "duckduckgo",
        "kl": country_language,
        "api_key":  SERP_API_KEY
        },{
        "engine": "yahoo",
        "api_key":  SERP_API_KEY,
        "vs":country_yahoo,
        "vl":"lang_" + lang_yahoo,
        },{
        "engine": "yandex",
        "api_key":  SERP_API_KEY,
        "lang":lang_yandex,
        "lr": 84
        }
        ]

    for idx, params in enumerate(paramsList):
        platform = params['engine']
        base_query = ''
        if platform == 'google' or platform == 'duckduckgo' :
            if title_query:
                base_query += "intitle:\"" + title_query + "\"" 

            if content_query:
                if base_query:
                    base_query += " " + combineOperator +" "  # Combining title and content queries
                base_query += "intext:\"" + content_query + "\""
            paramsList[idx]['q'] = base_query
        if platform == 'bing':
            if title_query:
                base_query += "intitle:\"" + title_query + "\"" 

            if content_query:
                if base_query:
                    base_query += " " + combineOperator +" "  # Combining title and content queries
                base_query += "inbody:\"" + content_query + "\""
            paramsList[idx]['q'] = base_query
            
        if platform == 'yandex' or platform  == 'yahoo':
            if title_query:
                base_query += "\"" + title_query + "\"" 

            if content_query:
                if base_query:
                    base_query += " " + combineOperator +" "  # Combining title and content queries
                base_query += "\"" + content_query + "\""
            if platform == 'yandex':
                paramsList[idx]['text'] = base_query
            if platform == 'yahoo':
                paramsList[idx]['p'] = base_query
            
    return paramsList

def convert_results_to_csv(results):
    csv_list = []

    # Header
    csv_list.append(','.join(['Domain', 'Occurrences', 'Title', 'Link', 'Link Occurrences', 'Engines']))

    # Data
    for domain, data in results.items():
        for link_data in data['links']:
            row = [
                domain,
                str(data['count']),
                link_data['title'],
                link_data['link'],
                str(link_data['count']),
                ', '.join(link_data['engines'])
            ]
            csv_list.append(','.join(row))

    return "\n".join(csv_list)

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
    return   [urlparse(row[4]).netloc.strip() for row in reader]# Assuming the URL column is the second column

if __name__ == "__main__":
    init_db()
    app.run(debug=True)