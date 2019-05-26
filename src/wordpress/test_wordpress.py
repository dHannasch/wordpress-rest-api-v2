
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
