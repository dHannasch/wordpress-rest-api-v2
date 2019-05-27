
import wordpress.api
import configparser
import requests


def test_credential():
  credential = wordpress.api.WordPressComCredential()
  tokenValid = requests.get(credential.get_verification_url(), proxies=wordpress.api.get_proxies(), verify=wordpress.api.get_verify())
  assert tokenValid.status_code == 200
  tokenValidJSON = tokenValid.json()
  assert tokenValidJSON['client_id'] == credential.client_id
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  assert tokenValidJSON['user_id'] == configParser['WordPressCom']['user_id']
  assert tokenValidJSON['blog_id'] == configParser['WordPressCom']['blog_id']

def test_v1_me():
  session = wordpress.api.make_session()
  response = requests.get(r'https://public-api.wordpress.com/rest/v1/me/',
                          headers=session.headers, proxies=session.proxies, verify=session.cert,
                          json=dict())
  assert response.status_code == 200
  assert response.headers['Content-Type'] == 'application/json'
  responseJSON = response.json()
  assert responseJSON['verified']
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  assert responseJSON['ID'] == int(configParser['WordPressCom']['user_id'])
  assert responseJSON['primary_blog'] == int(configParser['WordPressCom']['blog_id'])

def test_get_posts():
  response = wordpress.api.get_posts(wordpress.api.make_session(), wordpress.api.get_blog_url())
  assert response.status_code == 200
  assert response.headers['Content-Type'] == 'application/json; charset=UTF-8'
  assert response.headers['Access-Control-Allow-Headers'] == 'Authorization, Content-Type'
  # Access-Control-Allow-Headers sounds important but doesn't seem to matter:
  assert 'Authorization' not in response.request.headers
  assert 'Content-Type' not in response.request.headers
  assert len(response.request.headers) >= 4
  posts = response.json()
