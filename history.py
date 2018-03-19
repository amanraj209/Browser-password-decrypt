import os
import sqlite3
import operator
from collections import OrderedDict
import matplotlib.pyplot as plt

def parse_url(url):
    try:
        parsed_url_components = url.split('//')[1].split('/')[0]
        domain = parsed_url_components.replace('www.', '')
        return domain
    except IndexError:
        print(url)
        print('Invalid URL Format');

def analyze_history(history):
    prompt = input('[.] Type <c> to print or <p> to plot results\n[>]')
    
    if prompt == 'c':
        for site, count in sites_count_sorted.items():
            print('{} -> {}'.format(site, count))
    elif prompt == 'p':
        plt.bar(range(len(history)), history.values(), align='edge')
        plt.xticks(rotation=45)
        plt.xticks(range(len(history)), history.keys())
        plt.show()
    else:
        print('[.] Invalid input')
        quit()

if __name__ == '__main__':
    # Path to user's history database (Chrome)
    # For Mac
    data_path = os.path.expanduser('~') + '/Library/Application Support/Google/Chrome/Profile 3'
    
    # For Windows
    # data_path = os.path.expanduser('~') + '\AppData\Local\Google\Chrome\User Data\Default'
    
    files = os.listdir(data_path)
    
    history_db = os.path.join(data_path, 'History')
    
    # Querying the db
    db = sqlite3.connect(history_db)
    cursor = db.cursor()
    query_statement = 'SELECT urls.url, urls.visit_count FROM urls, visits WHERE urls.id = visits.url;'
    cursor.execute(query_statement)
    
    results = cursor.fetchall()
    
    sites_count = {}
    
    for url, count in results:
        url = parse_url(url)
        if url in sites_count:
            sites_count[url] += 1
        else:
            sites_count[url] = 1
            
    
    sites_count_sorted = OrderedDict(sorted(sites_count.items(), key=operator.itemgetter(1), reverse=True))
    
    analyze_history(sites_count_sorted)
        