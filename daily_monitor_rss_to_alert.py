import os
import feedparser
import pandas as pd
import smtplib
from io import BytesIO
import datetime

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from app import fetch_content_results
from dotenv import load_dotenv
from modules.email_utils import send_results_email


load_dotenv()

# Email credentials
EMAIL_USER = os.getenv("EMAIL_CREDS_USER")
EMAIL_PASS = os.getenv("EMAIL_CREDS_PASS")
EMAIL_SMTP = os.getenv("EMAIL_CREDS_SMTP")
RECIPIENT_EMAIL = "benzonip@gmail.com,julia.smirnova@cemas.io,saman.nazari@alliance4europe.eu"  # Change this to the actual recipient

# Path for caching searched URLs
CACHE_FILE = "searched_urls.csv"

# List of RSS feeds
RSS_FEEDS = [
    "https://zeitgeschenen.de/feed",
    "https://hamburger-anzeiger.de/feed",
    "https://hamburger-sichtweisen.de/feed",
    "https://nachrichtendestages.de/feed",
    "https://alles-klar-hamburg.de/feed",
    "https://n-a-h.de/feed",
    "https://hamburg-ex.de/feed",
    "https://das-denkt-hamburg.de/feed",
    "https://hamb-post.de/feed",
    "https://h-np.de/feed",
    "https://dznachrichten.de/feed",
    "https://stimmedeutsch.de/feed",
    "https://infomediafuerdich.de/feed",
    "https://doch-infomedia.de/feed",
    "https://prinzipienfest.de/feed",
    "https://in-absicht.de/feed",
    "https://kernpunkt-infomedia.de/feed",
    "https://info-stichpunkt.de/feed",
    "https://ausdemueberall.de/feed",
    "https://einfachandersinfo.de/feed",
    "https://thesis-info.de/feed",
    "https://newsfuereuch.de/feed",
    "https://nachrichtenunabhaengig.de/feed",
    "https://gegengewicht-media.de/feed",
    "https://la-cher.de/feed",
    "https://gegenleitmedien.de/feed",
    "https://deutschenachrichtenstelle.de/feed",
    "https://infomediaregierungskritisch.de/feed",
    "https://info-mediaplattform.de/feed",
    "https://diewahreseite.de/feed",
    "https://guckmalgenauhin.de/feed",
    "https://zeitenwende-news.de/feed",
    "https://aktuellde.de/feed",
    "https://internetpoebler-info.de/feed",
    "https://herrpostillon.de/feed",
    "https://newswichtig.de/feed",
    "https://unmittelbar-medien.de/feed",
    "https://mehrstimmen.de/feed",
    "https://aktuell-nachricht.de/feed",
    "https://allethemen24.de/feed",
    "https://ins-gesicht.de/feed",
    "https://aktuelles-aus-nurnberg.de/feed",
    "https://w-a-munchen.de/feed",
    "https://kernrecht.de/feed",
    "https://seite-eins-nachrichten.de/feed",
    "https://tagesnews-24.de/feed",
    "https://polemisch-infomedia.de/feed",
    "https://newsmacher.de/feed",
    "https://sag-das.de/feed",
    "https://in-und-ausland.de/feed",
    "https://nudis-verbis.de/feed",
    "https://expert-infomedien.de/feed",
    "https://de-nachrichtenseite.de/feed",
    "https://alles-wichtig-news.de/feed",
    "https://novanachrichten.de/feed",
    "https://vollverstand.de/feed",
    "https://dasneueste-online.de/feed",
    "https://munchener-nachrichten.de/feed",
    "https://tagundnacht24.de/feed",
    "https://laut-medien.de/feed",
    "https://rundumdieuhr-24.de/feed",
    "https://onlinedaheim-24.de/feed",
    "https://onlineunterwegs.de/feed",
    "https://ruf-der-freiheit.de/feed",
    "https://informant-info.de/feed"
]

# Load cached URLs
if os.path.exists(CACHE_FILE):
    cached_urls = set(pd.read_csv(CACHE_FILE)['url'])
else:
    cached_urls = set()

def fetch_rss_articles():
    articles = []
    for feed_url in RSS_FEEDS:
        feed = feedparser.parse(feed_url)
        for entry in feed.entries:
            if entry.link not in cached_urls:
                if (len(entry.title) < 40):  # Skip articles with short titles
                    continue
                articles.append({
                    'title': entry.title,
                    'excerpt': entry.summary if hasattr(entry, 'summary') else '',
                    'url': entry.link
                })
                cached_urls.add(entry.link)
    return articles

def process_articles(articles):
    processed_results = []
    for article in articles:
        results, _ = fetch_content_results(article['title'], article['excerpt'], 'OR', 'de', 'de',engines= ["bing", "yandex", "duckduckgo"])
        for result in results:
            if result['score'] < 70:
                break
            result.update({
                'searched_title': article['title'],
                'searched_excerpt': article['excerpt'],
                'searched_url': article['url']
            })
            processed_results.append(result)
    return processed_results

def send_email(results):
    if not results:
        print("No new results to send.")
        return

    # Create a DataFrame from results
    df = pd.DataFrame(results)

    # Prepare CSV file as BytesIO
    csv_buffer = BytesIO()
    df.to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)

    # Add date to subject
    subject = "Storm 1516 laundering Report for " + datetime.now().strftime("%d-%m-%Y") 
    body = "Attached are the new results from the RSS feed processing."

    # Send email with CSV attachment
    send_results_email(
        receiver_email=RECIPIENT_EMAIL,
        subject=subject,
        body=body,
        file=csv_buffer,
        filename="rss_feed_results.csv"
    )


def main():
    articles = fetch_rss_articles()
    results = process_articles(articles)
    send_email(results)

    # Update the cache
    pd.DataFrame({'url': list(cached_urls)}).to_csv(CACHE_FILE, index=False)

if __name__ == "__main__":
    main()
