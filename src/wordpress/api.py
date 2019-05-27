
import configparser
import urllib.parse
import requests
import typing

"""
When having authentication issues, we have options:
https://2.python-requests.org/en/master/user/advanced/
prepped.body = 'No, I want exactly this as the body.'
del prepped.headers['Content-Type']
"""

class WordPressComCredential:
  def __init__(self):
    configParser = configparser.ConfigParser()
    configParser.read('comsecrets.ini')
    try:
      self.rawToken = configParser['WordPressCom']['rawtoken']
    except KeyError:
      raise KeyError('Token not found in comsecrets.ini!')
    self.client_id = configParser['WordPressCom']['client_id']
  def get_encoded_token(self):
    return urllib.parse.quote(self.rawToken)
  def get_verification_url(self):
    return r'https://public-api.wordpress.com/oauth2/token-info?client_id={}&token={}'.format(self.client_id, self.get_encoded_token())

def get_blog_url() -> str:
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  return configParser['WordPressCom']['url']

def get_proxies() -> dict:
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  return {'http': configParser['Proxies']['http'], 'https': configParser['Proxies']['https']}

def get_verify() -> str:
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  return configParser['Proxies']['ssl_verify']

def make_session() -> requests.Session:
  """
  This can be used as a context manager.
  Any dictionaries that you pass to a request method will be merged with the session-level values that are set.
  https://2.python-requests.org/en/master/api/#request-sessions
  """
  ret = requests.Session()
  ret.cert = get_verify()
  ret.proxies = get_proxies()
  credential = WordPressComCredential()
  ret.headers = {"Authorization": "Bearer " + credential.rawToken}
  return ret

def get_posts(session: requests.Session, url: str):
  return requests.get(r'https://public-api.wordpress.com/wp/v2/sites/{}/posts'.format(url), proxies=session.proxies, verify=session.cert)

