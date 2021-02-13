import requests
from contextlib import closing
import codecs
import csv
import tldextract
import ipaddress as ip
import sys

inFile = sys.argv[1]

def is_ip(address):
    """Will extract tld from url and throw exception if not an IP address"""
    try:
        if ip.ip_address((tldextract.extract(address)).domain):
            return 1
    except:
        return 0


def domain_length(address):
    """Extracts domain from URL and count characters"""
    domain = tldextract.extract(address)
    return len(domain.domain)


def count_dots(address):
    """Count occurrences of dots in address"""
    count = address.count('.')
    return count


def is_malicious(classification):
    if classification == 'malicious':
        return 1
    else:
        return 0


def count_at(address):
    """Count occurrences of @ symbol"""
    count = address.count('@')
    return count


def is_redirect(address):
    """Count occurrences of //"""
    count = (address.count('//')) - 1
    return count


def count_symbols(address):
    """Count occurrences of symbols in full address"""
    count = address.count('?') + address.count('-') + address.count('_') + \
            address.count('~') + address.count('%') + address.count('$') + \
            address.count('!') + address.count('&') + address.count("'") + \
            address.count('(') + address.count(')') + address.count('*') + \
            address.count('+') + address.count(',') + address.count(';') + \
            address.count('=') + address.count('"')
    return count


def count_symbols_tld(address):
    """Count occurrences of symbols in domain"""
    count = count_symbols(tldextract.extract(address).domain)
    return count


def count_words(address):
    """Count occurrences of keywords in full address"""
    count = 0
    keywords = ['account', 'log', 'bcp', 'click', 'login',
                'update', 'secure', 'signin', 'confirm', 'signon',
                'user', 'billing']
    for word in keywords:
        if word in address:
            count = + 1
    return count


def count_words_tld(address):
    """Count occurrences of keywords in domain"""
    count = count_words(tldextract.extract(address).domain)
    return count


# Empty list to store URL dictionaries
urls = []


def extract_features(url_list, classification, number):
    """Extracts relevant features from URLs"""
    count = 1
    for row in url_list:  # deals with phishID column on PhishTank
        if classification is 'malicious':
            row = row[1]
        if classification is 'legitimate':
            row = row[0]
        urls.append({'url': row,
                     'classification': is_malicious(classification),
                     'url len': len(row),
                     'domain len': int(domain_length(row)),
                     'is IP': is_ip(row),
                     'dot count': count_dots(row),
                     'symbol count': count_symbols(row),
                     'symbol count_tld': count_symbols_tld(row),
                     'keywords': count_words(row),
                     'keywords_tld': count_words_tld(row),
                     'count @': count_at(row),
                     'is redirect': is_redirect(row)})
        count += 1
        if count > number:
            break


def pull_urls():
    """Uses PhishTank API to pull CSV and uses extracts features"""
    url = 'http://data.phishtank.com/data/<API-KEY>/online' \
          '-valid.csv'
    with closing(requests.get(url, stream=True)) as r:
        reader = csv.reader(codecs.iterdecode(r.iter_lines(), 'utf-8'), delimiter=',', quotechar='"')
        next(reader, None)  # Skip header row
        extract_features(reader, 'malicious', 200)


def read_csv():
    """Reads legitimate CSV file and extracts features"""
    with open(inFile, 'r') as f:
        reader = csv.reader(f)
        next(reader, None)  # Skip header row
        extract_features(reader, 'legitimate', 200)


# Call functions
pull_urls()
read_csv()

# writes URL list to CSV file
keys = urls[0].keys()
with open('urls.csv', 'w') as output_file:
    dict_writer = csv.DictWriter(output_file, keys)
    dict_writer.writeheader()
    dict_writer.writerows(urls)
