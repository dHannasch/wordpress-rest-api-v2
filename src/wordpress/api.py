
import configparser
import urllib.parse

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

def get_proxies():
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  return {'http': configParser['Proxies']['http'], 'https': configParser['Proxies']['https']}

def get_verify():
  configParser = configparser.ConfigParser()
  configParser.read('comsecrets.ini')
  return configParser['Proxies']['ssl_verify']
