import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import time
import re

# sites to ignore =
ignore_sites = ['43things.com',
                'academia.edu',
                'Advogato.org',
                'ANobii.com',
                'Asianave.com',
                'aSmallWorld.net',
                'Athlinks.com',
                'Audimated.com',
                'bebo.com#',
                'Biip.no',
                'BlackPlanet.com',
                'blauk.com',
                'blogster.com#',
                'www.bolt.com',
                'busuu.com',
                'Buzznet.com',
                'CafeMom.com',
                'Care2.com',
                'caringbridge.org',
                'Classmates.com',
                'Cloob.com',
                'CouchSurfing.org',
                'CozyCot.com',
                'cross.tv',
                'crunchyroll.com',
                'cyworld.com',
                'DailyBooth.com',
                'DailyStrength.org',
                'delicious.com',
                'deviantART.com',
                'joindiaspora.com',
                'Disaboom.com',
                'Dol2day.de',
                'DontStayIn.com',
                'Draugiem.lv',
                'douban.com',
                'dxy.cn',
                'Elftown.com',
                'elixio.net#',
                'englishbaby.com',
                'Epernicus.com',
                'Eons.com',
                'etoro.com#',
                'ExperienceProject.com',
                'Exploroo.com',
                'Facebook.com',
                'Faceparty.com',
                'Faces.com',
                'Fetlife.com',
                'FilmAffinity.com',
                'filmow.com',
                'FledgeWing.com',
                'Flixster.com',
                'Flickr.com',
                'focus.com',
                'formspring.me',
                'fotki.com',
                'Fotolog.com',
                'Foursquare.com',
                'friendica.com',
                'FriendsReunited.co.uk',
                'Friendster.com',
                'Fruehstueckstreff.de',
                'fuelmyblog.com',
                'fullcircle.net',
                'GaiaOnline.com',
                'GamerDNA.com',
                'gapyear.com',
                'Gather.com',
                'Gays.com',
                'Geni.com',
                'GetGlue.com',
                'gogoyoko.com',
                'Goodreads.com',
                'goodwizz.com',
                'govloop.com',
                'Grono.net',
                'Habbo.com',
                'Hi5.com',
                'HospitalityClub.org',
                'hotlist.com',
                'hr.com',
                'hubculture.com',
                'Hyves.nl',
                'Ibibo.com',
                'indenti.ca',
                'www.indabamusic.com',
                'IRC-Galleria.net',
                'Italki.com',
                'Itsmy.com',
                'iWiW.hu',
                'Jaiku.com',
                'Jiepang.com',
                'Kaixin001.com',
                'Kiwibox.com',
                'lafango.com',
                'laibhaari.com',
                'Last.fm',
                'LibraryThing.com',
                'Lifeknot.com',
                'LinkedIn.com',
                'linkexpats.com',
                'Listography.com',
                'LiveJournal.com',
                'Livemocha.com',
                'makeoutclub.com',
                'MEETin.org',
                'Meetup.com',
                'Meettheboss.tv',
                'mymfb.com',
                'mixi.jp',
                'MocoSpace.com',
                'MOG.com',
                'MouthShut.com',
                'mubi.com',
                'MyHeritage.com',
                'MyLife.com',
                'MySpace.com',
                'Nasza-klasa.pl',
                'netlog.com',
                'Netlog.com',
                'Nexopia.com',
                'NGOPost.org',
                'Ning.com',
                'Odnoklassniki.ru',
                'OpenDiary.com',
                'Orkut.com',
                'OUTeverywhere.com',
                'patientslikeme.com',
                'partyflock.nl',
                'Pingsta.com',
                'pinterest.com',
                'Plaxo.com',
                'playfire.com',
                'playlist.com',
                'Plurk.com',
                'poolwo.com',
                'Qapacity.com',
                'quechup.com',
                'raptr.com',
                'Ravelry.com',
                'Renren.com',
                'ReverbNation.com',
                'Ryze.com',
                'sciencestage.com',
                'ShareTheMusic.com',
                'Shelfari.com',
                'weibo.com',
                'www.skoob.com.br',
                'SkyRock.com',
                'SocialVibe.com',
                'Sonico.com',
                'soundcloud.com',
                'spaces.ru#',
                'Stickam.com',
                'StudiVZ.net',
                'studentscircle.net',
                'StumbleUpon.com',
                'Tagged.com',
                'Talkbiznow.com',
                'Taltopia.com',
                'Taringa.net',
                'teachstreet.com',
                'termwiki.com',
                'the-sphere.com',
                'TravBuddy.com',
                'TravellersPoint.com',
                'Tribe.net',
                'Trombi.com',
                'Tuenti.com',
                'tumblr.com',
                'Twitter.com',
                'Cellufun.com',
                'vk.com',
                'VampireFreaks.com',
                'Viadeo.com',
                'Virb.com',
                'Vox.com',
                'wattpad.com',
                'WAYN.com',
                'weeworld.com',
                'weheartit.com',
                'wellwer.com',
                'WeOurFamily.com',
                'wepolls.com',
                'wer-kennt-wen.de',
                'weread.com',
                'Wiser.org',
                'Wooxie.com',
                'writeaprisoner.com',
                'Xanga.com',
                'XING.com',
                'Xt3.com',
                'Yammer.com',
                'Yelp.com',
                'Zoo.gr',
                'zooppa.com']

for item in ignore_sites:
    item.lower()

visited = set()
verification_tuples = []


def valid_url(url):
    # Regular expression for matching a URL
    regex = r'^(?:http|ftp)s?://'

    # If the URL does not match the regular expression
    if not re.match(regex, url):
        url = url.strip("/")
        # Add the 'http://' prefix to the URL
        url = 'http://' + url
    if url == 'http://':
        return ""

    return url


def get_domain_name(url):
    # Parse the URL using urlparse
    parsed_url = urlparse(url)

    # Get the domain name from the netloc attribute
    domain_name = parsed_url.netloc

    # Remove the www. prefix from the domain name
    if domain_name.startswith('www.'):
        domain_name = domain_name[4:]

    return domain_name


def get_ip_address(domain_name):

    if domain_name.startswith('https://'):
        domain_name = domain_name[8:]

    try:
        # Resolve the domain name to an IP address
        ip_address = socket.gethostbyname(domain_name)
        print("The IP address of the domain name {} is {}".format(
            domain_name, ip_address))
    except socket.gaierror:
        print("Could not resolve the domain name {}".format(domain_name))


def crawl(url, visited_urls):
    # Add the URL to the set of visited URLs
    visited_urls.add(get_domain_name(url))
    # Send a GET request to the specified URL
    response = requests.get(url)

    # Parse the HTML content of the page
    soup = BeautifulSoup(response.text, 'html.parser')

    # Print the DOM
    print(url)
    get_ip_address(url)
    w = whois.whois(url)
    verification_tuples.append(('whois', w, get_domain_name(url)))
    print(w)

    meta_tags = soup.find_all('meta')

    # Iterate over the meta tags
    for meta_tag in meta_tags:
        # Get the name and content attributes of the meta tag
        name = meta_tag.get('name')
        content = meta_tag.get('content')
        # Print the name and content attributes
        if name and 'verification' in name:
            print(f'name: {name}, content: {content}')
        t = ('verification-id', name, content, get_domain_name(url))
    with open('soup.html', 'w', encoding='utf-8', errors='ignore') as file:
        # Write the prettified HTML content to the file
        file.write(soup.prettify())

    # Find all the links in the page
    links = soup.find_all('a')
    for link in links:
        # Get the href attribute of the link
        href = link.get('href')

        # If the href attribute is not empty
        if href:
            href = valid_url(href)
            # If the URL has not been visited yet
            if get_domain_name(href) not in visited_urls and href != "":

                # Follow the link
                time.sleep(1)
                try:
                    #crawl(href, visited_urls)
                    print()
                except Exception:
                    continue

visited_urls = set()
# Start the crawler at a specific URL
crawl('https://www.oklahomastar.com', visited_urls)
