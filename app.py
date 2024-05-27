from flask import Flask, request, render_template
import requests
import re

app = Flask(__name__)

def check_url(url):
    api_key = 'AIzaSyAMD8lY4V1YUso9XGL7hdHj1YcoFoMw1go'
    api_endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
    payload = {
        "client": {
            "clientId": "19946958563-hfvrts596lr72q3sqemmab23ut0dgusu.apps.googleusercontent.com",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_endpoint, json=payload)
    if response.status_code == 200:
        data = response.json()
        if data.get('matches'):
            return True
    return False

@app.route('/')
def home():
    return render_template('index.html', message=None)

@app.route('/', methods=['POST'])
def check():
    url = request.form['url']
    if not re.match(r'^https?://(?:[-\w]+\.)?([-\w]+\.[a-z]{2,4})', url):
        return render_template('index.html', message='Invalid URL format.')
    result = check_url(url)
    if result:
        return render_template('index.html', message=f'{url} is a phishing website!')
    else:
        return render_template('index.html', message=f'{url} is safe to access.')

if __name__ == '__main__':
    app.run(debug=True)
