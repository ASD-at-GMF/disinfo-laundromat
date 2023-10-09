from flask import Flask, render_template, request, flash
from flask_bootstrap import Bootstrap
import requests

from urllib.parse import urlparse
import csv

# Paramaterizable Variables
from config import SERP_API_KEY
# Import all your functions here
from crawler import *

app = Flask(__name__)
Bootstrap(app)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/fingerprint', methods=['GET', 'POST'])
def fingerprint():
    url = ''
    if request.method == 'POST':
        url = request.form['url']
        # Do something with the url using your functions
        try:
            indicators = crawl(url, set())
            write_indicators(indicators, output_file="indicators2.csv")
            indicators_df = pd.read_csv("indicators2.csv")  # read the csv file
            return render_template('success.html', url=url, table=indicators_df.to_html(index=False))  # convert dataframe to html table
 
        except Exception as e:
            return render_template('error.html', error=e)

    return render_template('index.html')


@app.route('/content', methods=['GET', 'POST'])
def content():
    results = None

    if request.method == 'POST':
        title_query = request.form.get('titleQuery')
        content_query = request.form.get('contentQuery')
        
        if not title_query and not content_query:
            # Error message if neither is provided
            flash("Please provide at least a title or content query.")
        else:
            results = fetch_results(title_query, content_query)

    return render_template('index.html', results=results)

# TODO Federate this out 
def fetch_results(title_query, content_query):
    domains_of_concern = load_domains_of_concern()
     # Parameters for SERPAPI Google integration
    results = fetch_serp_results(title_query, content_query)
    
    # Flagging domains of concern
    for domain, data in results.items():
        data["concern"] = domain in domains_of_concern

    return results

def fetch_serp_results(title_query, content_query):
    paramsList = customize_params_by_platform(title_query, content_query)                  
    aggregated_results = {}
    for params in paramsList:
        search_engine = params["engine"]
        base_url = "https://serpapi.com/search"  # base url of the API
        response = requests.get(base_url, params=params)
        data = response.json()
        organic_results = data.get("organic_results", [])
        print( params)

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

    return aggregated_results

def customize_params_by_platform(title_query, content_query):
    paramsList = [
        {
        "engine": "google",
        "location": "United States",
        "hl": "en",
        "gl": "us",
        "google_domain": "google.com",
        "num": 40,
        "api_key": SERP_API_KEY
        },{
        "engine": "bing",
        "mkt": "en-US",
        "count": 40,
        "api_key":  SERP_API_KEY
        },{
        "engine": "duckduckgo",
        "kl": "us-en",
        "api_key":  SERP_API_KEY
        },{
        "engine": "yahoo",
        "api_key":  SERP_API_KEY,
        "vs":"us",
        "vl":"en"
        },{
        "engine": "yandex",
        "api_key":  SERP_API_KEY,
        "lang":"en",
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
                    base_query += " AND "  # Combining title and content queries
                base_query += "intext:\"" + content_query + "\""
            paramsList[idx]['q'] = base_query
        if platform == 'bing':
            if title_query:
                base_query += "intitle:\"" + title_query + "\"" 

            if content_query:
                if base_query:
                    base_query += " AND "  # Combining title and content queries
                base_query += "inbody:\"" + content_query + "\""
            paramsList[idx]['q'] = base_query
            
        if platform == 'yandex' or platform  == 'yahoo':
            if title_query:
                base_query += "\"" + title_query + "\"" 

            if content_query:
                if base_query:
                    base_query += " AND "  # Combining title and content queries
                base_query += "\"" + content_query + "\""
            if platform == 'yandex':
                paramsList[idx]['text'] = base_query
            if platform == 'yahoo':
                paramsList[idx]['p'] = base_query
            
    return paramsList

def load_domains_of_concern(filename="sites_of_concern.csv"):
    with open(filename, mode="r", encoding="utf-8") as file:
        reader = csv.reader(file)
        next(reader)  # skip header
        return [urlparse(row[1].strip()).netloc for row in reader]

if __name__ == "__main__":
    app.run(debug=True)