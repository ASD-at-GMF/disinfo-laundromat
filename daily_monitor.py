import os
import pandas as pd
from sqlalchemy import create_engine, text
from io import StringIO, BytesIO
from flask import send_file
from app import fetch_content_results
from dotenv import load_dotenv
load_dotenv()
import zipfile

from sqlalchemy import create_engine
from sqlalchemy.engine import URL

from sqlalchemy import create_engine

# Simplified connection string
source_connection_string = os.getenv('HAMILTON_DATABASE_URL')
source_engine = create_engine(source_connection_string)

target_connection_string = os.getenv('PRODUCTION_DATABASE_URL')
target_engine = create_engine(target_connection_string)

articles_query = os.getenv('ARTICLES_RETRIEVAL_QUERY_DAILY')  # Adjust query according to your schema


# Function to articles
def fetch_articles(limit=5):
    query = text(articles_query)
    with source_engine.connect() as conn:
        result = conn.execute(query)
        articles = pd.DataFrame(result.fetchall(), columns=result.keys())
    return articles


# Process each article through the laundromat
def process_article(title, content, language, engines = ['google', 'google_news', 'bing', 'bing_news', 'yahoo', 'duckduckgo', 'yandex', 'gdelt', 'copyscape']):
    return fetch_content_results(title, content, 'OR', language, 'us', engines=engines)

# Save results to content_queries_results_hamilton in the target database
def save_results_to_target_db(results):
    try:
        results = results.drop(['engine', 'source'], axis=1)
        results.to_sql('content_queries_results_hamilton', target_engine, if_exists='append', index=False)
    except Exception as e:
        print(f"Error saving results to target database: {e}")


def main():
    # Fetch articles
    articles = fetch_articles()

    # Process articles iteratively
    processed_data = []

    for idx, row in articles.iterrows():
        results, csv_data = process_article( row['title'], row['excerpt'], row['langTranslated'])
        for result in results:
            result.update({"searched_site": row['site'] , 'searched_published': row['published'], "searched_title": row['title'], "searched_excerpt": row['excerpt'], "searched_langtranslated": row['langTranslated'], 'searched_titletranslated':row['titleTranslated'], 'searched_excerpttranslated':row['excerptTranslated'], 'searched_url':row['url']})
        save_results_to_target_db(pd.DataFrame(results))
        print(f"Processed article: {row}")

    # Save results to content_queries_results_hamilton in the target database
    

if __name__ == "__main__":
    main()