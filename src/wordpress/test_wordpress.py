
import wordpress.api
import configparser
import requests
import requests_kerberos
import urllib.parse
import subprocess
import webbrowser
import pytest


@pytest.mark.com
def test_authorization_url():
  """
  This is also a good way to get the blog_id and rawtoken if you know a username and password but not those.
  """
  credential = wordpress.api.WordPressComCredential()
  credential.visit_authorization_url()

@pytest.mark.com
def test_head():
  session = wordpress.api.make_session_without_credential()
  response = requests.head(r'https://public-api.wordpress.com/wp/v2/', proxies=session.proxies, verify=session.cert)
  assert response.status_code == 200
  assert response.headers['Content-Type'] == 'application/json; charset=UTF-8'
  assert response.headers['Access-Control-Allow-Headers'] == 'Authorization, Content-Type'

def test_multisite_head():
  session = wordpress.api.make_kerberos_session()
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  wpv2 = urllib.parse.urljoin(configParser['WordPressMultisite']['multisite_base_url'], 'wp-json/wp/v2/')
  response = requests.head(wpv2,
                           auth=session.auth,
                           proxies=session.proxies, verify=session.cert,
                           )
  assert response.status_code == 200
  assert response.headers['Content-Type'] == 'application/json; charset=UTF-8'
  assert response.headers['Access-Control-Allow-Headers'] == 'Authorization, Content-Type'

@pytest.mark.com
def test_root():
  session = wordpress.api.make_session_without_credential()
  response = requests.get(r'https://public-api.wordpress.com/wp/v2/', proxies=session.proxies, verify=session.cert)
  assert response.status_code == 200
  assert response.headers['Content-Type'] == 'application/json; charset=UTF-8'
  assert response.headers['Access-Control-Allow-Headers'] == 'Authorization, Content-Type'
  responseJSON = response.json()
  assert 'authentication' not in responseJSON
  assert 'namespaces' not in responseJSON

def test_multisite_root():
  session = wordpress.api.make_kerberos_session()
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  wpv2 = urllib.parse.urljoin(configParser['WordPressMultisite']['multisite_base_url'], 'wp-json/wp/v2/')
  response = requests.get(wpv2,
                           auth=session.auth,
                           proxies=session.proxies, verify=session.cert,
                           )
  assert response.status_code == 200
  assert response.headers['Content-Type'] == 'application/json; charset=UTF-8'
  assert response.headers['Access-Control-Allow-Headers'] == 'Authorization, Content-Type'
  responseJSON = response.json()
  assert 'authentication' not in responseJSON
  assert 'namespaces' not in responseJSON

# At the moment there are no endpoints explicitly for multisite,
# so you can't e.g. get a list of sites from /sites/ or any such thing.
# It was suggested, but never implemented: https://make.wordpress.org/core/2017/01/25/providing-a-rest-api-sites-endpoint-for-multisite/

@pytest.mark.com
def test_credential():
  credential = wordpress.api.WordPressComCredential()
  tokenValid = requests.get(credential.get_verification_url(), proxies=wordpress.api.get_proxies(), verify=wordpress.api.get_verify())
  assert tokenValid.status_code == 200
  tokenValidJSON = tokenValid.json()
  assert tokenValidJSON['client_id'] == credential.client_id
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  assert tokenValidJSON['blog_id'] == configParser['WordPressCom']['blog_id']
  assert tokenValidJSON['user_id'] == configParser['WordPressCom']['user_id']

@pytest.mark.com
def test_v1_me():
  session = wordpress.api.WordPressComCredential().make_session()
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

@pytest.mark.com
def test_get_posts():
  site = wordpress.api.WordPressComSite()
  response = site.get_posts(wordpress.api.make_session_without_credential())
  assert response.status_code == 200
  assert response.headers['Content-Type'] == 'application/json; charset=UTF-8'
  assert response.headers['Access-Control-Allow-Headers'] == 'Authorization, Content-Type'
  # Access-Control-Allow-Headers sounds important but doesn't seem to matter:
  assert 'Authorization' not in response.request.headers
  assert 'Content-Type' not in response.request.headers
  assert len(response.request.headers) >= 4
  posts = response.json()

@pytest.mark.com
def test_get_pages():
  site = wordpress.api.WordPressComSite()
  credential = wordpress.api.WordPressComCredential()
  # temporary hack so we have a working test while refactoring with the knowledge that we need edit permissions to retrieve raw pages:
  site.download_pages(session=credential.make_session())
  credential.upload_pages()

def test_get_multisite_pages():
  site = wordpress.api.WordPressMultisiteSite()
  site.download_pages()
  credential = wordpress.api.WordPressMultisiteCredential(site)
  credential.upload_pages(site.directory_to_save_pages(), site.make_session())

def test_multisite_acf():
  session = wordpress.api.make_kerberos_session()
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  site_url = urllib.parse.urljoin(configParser['WordPressMultisite']['multisite_base_url'], configParser['WordPressMultisite']['site_path'])
  acfv3 = urllib.parse.urljoin(site_url, 'wp-json/acf/v3/')
  response = requests.get(urllib.parse.urljoin(acfv3, 'pages/221'), auth=session.auth, proxies=session.proxies, verify=session.cert)
  assert response.status_code == 200
  assert response.headers['Content-Type'] == 'application/json; charset=UTF-8'
  assert response.headers['Access-Control-Allow-Headers'] == 'Authorization, Content-Type'
  assert 'Content-Type' not in response.request.headers
  assert len(response.request.headers) >= 4
  #raise Exception(response.json())
  # It appears that /acf/v3/pages/ only returns top-level pages with no parent? to get the ACF content, have to request each page individually?
  #wordpress.api.save_pages(response.json(), configParser['WordPressMultisite']['site_path'])



