
import configparser
import urllib.parse
import requests
import requests_oauthlib, oauthlib
import requests_kerberos
import typing
import abc
import http.server
import webbrowser
import selenium.webdriver
from selenium.webdriver.support import expected_conditions # must be from-import?
import sys
import os
import json
import itertools
import difflib

"""
When having authentication issues, we have options:
https://2.python-requests.org/en/master/user/advanced/
prepped.body = 'No, I want exactly this as the body.'
del prepped.headers['Content-Type']
"""

class GetRecordingHandler(http.server.BaseHTTPRequestHandler):
  driver = None
  URLs = list()
  def do_GET(self):
    self.send_response(200)
    self.send_header('Content-type','text/html')
    self.end_headers()
    self.wfile.write(bytes("<html><head><title>Title goes here.</title></head>", "utf-8"))
    self.wfile.write(bytes("<body><p>This is a test.</p>", "utf-8"))
    assert self.path == '/'
    # arguments *should* be in self.path but are not: https://stackoverflow.com/questions/8928730/processing-http-get-input-parameter-on-server-side-in-python
    self.wfile.write(bytes("<p>You accessed path: %s</p>" % self.path, "utf-8"))
    self.wfile.write(bytes(GetRecordingHandler.driver.current_url, "utf-8"))
    GetRecordingHandler.URLs.append(GetRecordingHandler.driver.current_url)
    # The part of the URL after the hash is not sent to the server: https://stackoverflow.com/questions/940905/can-i-read-the-hash-portion-of-the-url-on-my-server-side-application-php-ruby
    # Exceptions raised here are hard to retrieve, so we store the raw URL to be parsed later.
    self.wfile.write(bytes(self.requestline, "utf-8"))
    self.wfile.write(bytes(str(self.headers), "utf-8"))
    self.wfile.write(bytes("</body></html>", "utf-8"))

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

def wordpress_link_to_file_path(link):
  parseResult = urllib.parse.urlparse(link)
  path = parseResult.path.lstrip('/')
  assert path[-1] == '/'
  # We strip the *leading* (but not the trailing) slash.
  return path

def save_pages(pages, directoryToSaveIn='savedPages'):
  # https://developer.wordpress.org/rest-api/reference/pages/
  # page['parent'] is an integer like page['id']
  # page['slug'] is only the very last child part of page['link']
  os.makedirs(directoryToSaveIn, exist_ok=True)
  with open(os.path.join(directoryToSaveIn, 'pages.json'), 'w') as pagesFile:
    json.dump(pages, pagesFile)
  for page in pages:
    directoryToSaveThisPage = os.path.join(directoryToSaveIn, wordpress_link_to_file_path(page['link']))
    assert directoryToSaveThisPage[-1] == '/'
    os.makedirs(directoryToSaveThisPage, exist_ok=True)
    content = page['content']
    assert not content['protected']
    assert len(content.keys()) == 2
    with open(os.path.join(directoryToSaveThisPage, 'content.rendered.html'), 'w') as pageFile:
      pageFile.write(content['rendered'])
    with open(os.path.join(directoryToSaveThisPage, 'id'), 'w') as IDfile:
      IDfile.write(str(page['id']))

def make_session_without_credential() -> requests.Session:
  """
  This can be used as a context manager.
  Any dictionaries that you pass to a request method will be merged with the session-level values that are set.
  https://2.python-requests.org/en/master/api/#request-sessions
  """
  ret = requests.Session()
  ret.cert = get_verify()
  ret.proxies = get_proxies()
  return ret

def make_kerberos_session() -> requests.Session:
  ret = requests.Session()
  ret.auth = requests_kerberos.HTTPKerberosAuth(mutual_authentication=requests_kerberos.OPTIONAL)
  return ret

def print_diff(a, b):
    for i,s in enumerate(difflib.ndiff(a, b)):
        if s[0]==' ': continue
        elif s[0]=='-':
            print(u'Delete "{}" from position {}'.format(s[-1],i))
        elif s[0]=='+':
            print(u'Add "{}" to position {}'.format(s[-1],i))

class WordPressComCredential:
  def __init__(self):
    self.configParser = configparser.ConfigParser()
    self.configParser.read('comsecrets.ini')
    try:
      self.rawToken = self.configParser['WordPressCom']['rawtoken']
    except KeyError:
      raise KeyError('Token not found in comsecrets.ini!')
    self.client_id = self.configParser['WordPressCom']['client_id']
    self.blog_id = self.configParser['WordPressCom']['blog_id']
    self.site = WordPressComSite()
  def get_user_name(self):
    return self.configParser['WordPressCom']['user_name']
  def get_password(self):
    return self.configParser['WordPressCom']['password']
  def get_encoded_token(self):
    return urllib.parse.quote(self.rawToken)
  def make_session(self) -> requests.Session:
    """
    This can be used as a context manager.
    Any dictionaries that you pass to a request method will be merged with the session-level values that are set.
    https://2.python-requests.org/en/master/api/#request-sessions
    """
    ret = make_session_without_credential()
    ret.headers = {"Authorization": "Bearer " + self.rawToken}
    return ret

  def get_app_url(self):
    """
    This is where you'll need to go to:
      add/change redirect URLs
    """
    return r'https://developer.wordpress.com/apps/{}/'.format(self.client_id)
  def visit_app_url(self):
    webbrowser.open(self.get_app_url())

  def get_verification_url(self):
    return r'https://public-api.wordpress.com/oauth2/token-info?client_id={}&token={}'.format(self.client_id, self.get_encoded_token())
  def get_authorization_url(self):
    redirect_uri = r'https%3a%2f%2fexample.com'
    # Since the token is going to be right there in the URL, using HTTPS doesn't make us any more secure.
    # To use HTTPS, we'd need a certificate.
    redirect_uri = r'http%3a%2f%2flocalhost:8080' # works
    redirect_uri = r'http%3A%2F%2Flocalhost%3A8080' # this just makes it easier to verify the library is giving the same
    client = oauthlib.oauth2.MobileApplicationClient(self.client_id)
    session = requests_oauthlib.OAuth2Session(self.client_id, client, redirect_uri=r'http://localhost:8080')
    session.cert = get_verify()
    session.proxies = get_proxies()
    state = session.new_state() # just a random string
    ret = r'https://public-api.wordpress.com/oauth2/authorize?response_type=token&client_id={}&redirect_uri={}&state={}&blog={}'.format(
        self.client_id, redirect_uri, state, self.site.blog_url)
    fromlib = session.authorization_url(r'https://public-api.wordpress.com/oauth2/authorize', state, blog=self.site.blog_url)
    if ret != fromlib[0]:
      print_diff(ret, fromlib[0])
      raise Exception('\n' + ret + '\n' + fromlib[0])
    # According to https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#mobile-application-flow
    # we can then just call session.get(),
    # but that doesn't make sense to me since the actual user hasn't authorized anything.
    # Trying to call as they say to results in inscrutable SSL errors.
    # The docs give no hint as to why they would expect this to work.
    # Their examples do not use session.get: https://requests-oauthlib.readthedocs.io/en/latest/examples/github.html
    # For now we'll just carry on returning the URL and using it to authorize separately.
    #response = session.get(ret)
    #session.token_from_fragment(response.url)
    return ret

  def visit_authorization_url(self):
    server = http.server.HTTPServer(('localhost', 8080), GetRecordingHandler)
    executable_path=os.path.join(os.path.dirname(sys.executable), 'geckodriver')
    GetRecordingHandler.driver = selenium.webdriver.Firefox(executable_path=executable_path)
    GetRecordingHandler.driver.get(self.get_authorization_url())
    usernameTextBox = selenium.webdriver.support.ui.WebDriverWait(GetRecordingHandler.driver, 5).until(
        expected_conditions.presence_of_element_located((
            selenium.webdriver.common.by.By.ID, 'usernameOrEmail')))
    usernameTextBox.send_keys(self.get_user_name())
    usernameTextBox.submit()
    passwordTextBox = selenium.webdriver.support.ui.WebDriverWait(GetRecordingHandler.driver, 5).until(
        expected_conditions.element_to_be_clickable((
            selenium.webdriver.common.by.By.ID, 'password')))
    passwordTextBox.send_keys(self.get_password())
    passwordTextBox.submit()
    approveButton = selenium.webdriver.support.ui.WebDriverWait(GetRecordingHandler.driver, 5).until(
        expected_conditions.element_to_be_clickable((
            selenium.webdriver.common.by.By.ID, 'approve')))
    approveButton.click()
    server.handle_request()
    GetRecordingHandler.driver.close()
    parseResult = urllib.parse.urlparse(GetRecordingHandler.URLs[-1])
    # ParseResult(scheme='http', netloc='localhost:8080', path='/', params='', query='',
    # fragment='access_token=blahblahblah&expires_in=1209600&token_type=bearer&site_id=1234&scope=')
    # Sometimes the query is where it should be and not in the fragment:
    # ParseResult(scheme='https', netloc='public-api.wordpress.com', path='/oauth2/authorize', params='',
    # query='client_id=12345&redirect_uri=http%3a%2f%2flocalhost:8080&response_type=token&blog=example.com',
    # fragment='')
    # That actually means we grabbed the URL before it successfully redirected...
    # but that's impossible because we shouldn't grab the URL until we RECEIVE the request to localhost...
    # The browser/driver must have sent the request to localhost
    if parseResult.query != '' or parseResult.netloc!='localhost:8080' or parseResult.params!='':
      raise Exception(parseResult)
    queryArgs = urllib.parse.parse_qs(parseResult.fragment)
    if 'expires_in' not in queryArgs:
      raise Exception(queryArgs)
    assert 'scope' not in queryArgs
    assert len(queryArgs['token_type']) == 1 and queryArgs['token_type'][0] == 'bearer'
    assert len(queryArgs['site_id']) == 1 and queryArgs['site_id'][0] == self.blog_id
    assert len(queryArgs['access_token']) == 1
    access_token = queryArgs['access_token'][0]
    if access_token != self.rawToken:
      raise Exception('Token has changed:' + access_token)
    #if access_token != requests_oauthlib.OAuth2Session().token_from_fragment(GetRecordingHandler.URLs[-1]):
    #  raise Exception(access_token, GetRecordingHandler.URLs[-1])
    #  throws an exception because http://localhost is HTTP rather than HTTPS

  def upload_pages(self, directoryOfPages=None):
    if not directoryOfPages:
      directoryOfPages = self.site.blog_url
    session = self.make_session()
    with open(os.path.join(directoryOfPages, 'pages.json'), 'r') as pagesFile:
      pages = json.load(pagesFile)
    for root, dirs, files in itertools.dropwhile(lambda t: t[0]==directoryOfPages, os.walk(directoryOfPages)):
      assert 'content.rendered.html' in files
      assert 'id' in files
      ID = int(open(os.path.join(root, 'id'), 'r').read())
      matchingPages = [page for page in pages if page['id'] == ID]
      assert len(matchingPages) == 1
      recordOfPage = matchingPages[0]
      if wordpress_link_to_file_path(recordOfPage['link']) != os.path.relpath(root, directoryOfPages) + '/':
        raise Exception(recordOfPage['link'], wordpress_link_to_file_path(recordOfPage['link']), os.path.relpath(root, directoryOfPages), root)
      pagePath = os.path.relpath(root, directoryOfPages) + '/'
      if pagePath == 'contact/':
        continue
      content = open(os.path.join(root, 'content.rendered.html'), 'r').read()
      pageURL = urllib.parse.urljoin(self.site.pages_url(), str(ID))
      # https://stackoverflow.com/questions/10893374/python-confusions-with-urljoin
      client = oauthlib.oauth2.MobileApplicationClient(self.client_id, token_type='bearer', access_token=self.rawToken)
      # https://github.com/requests/requests-oauthlib/blob/master/requests_oauthlib/oauth2_auth.py
      auth = requests_oauthlib.OAuth2(self.client_id, #client,
                                      token={'access_token': self.rawToken, 'token_type': 'bearer'},
                                      )
      response = requests.post(pageURL,
                               auth=auth,#headers=session.headers,
                               proxies=session.proxies, verify=session.cert,
                               json={'content': content})
      if response.status_code != 200:
        raise Exception(pagePath, pageURL, response, response.headers, response.content)
      responseJSON = response.json()
      assert responseJSON['id'] == ID
      assert wordpress_link_to_file_path(responseJSON['link']) == pagePath
      assert responseJSON['content']['raw'] == content

class WordPressSite(metaclass=abc.ABCMeta):
  @abc.abstractmethod
  def base_wp_v2_url(self) -> str:
    pass
  @abc.abstractmethod
  def make_session(self) -> requests.Session:
    """
    This can be used as a context manager.
    Any dictionaries that you pass to a request method will be merged with the session-level values that are set.
    https://2.python-requests.org/en/master/api/#request-sessions
    """
    return make_session_without_credential()

  def get_posts(self, session: requests.Session = None):
    session = session if session is not None else self.make_session()
    return requests.get(urllib.parse.urljoin(self.base_wp_v2_url(), 'posts'), proxies=session.proxies, verify=session.cert)
  def pages_url(self) -> str:
    """
    When using the /pages URL by itself, it makes no difference whether we include a / at the end.
    But if we use urllib.parse.urljoin later, we will get just /26 instead of /pages/26 unless we include a / at the end here.
    """
    noSlashAtEnd = urllib.parse.urljoin(self.base_wp_v2_url(), 'pages')
    return noSlashAtEnd + '/'
  def get_pages(self, session: requests.Session = None):
    # https://developer.wordpress.org/rest-api/reference/pages/
    session = session if session is not None else self.make_session()
    return requests.get(self.pages_url(), proxies=session.proxies, verify=session.cert)

  @abc.abstractmethod
  def get_pages_json(self, session: requests.Session=None):
    pass

class WordPressComSite(WordPressSite):
  def __init__(self, blog_url=get_blog_url()):
    self.blog_url = blog_url
  def base_wp_v2_url(self) -> str:
    """
    https://developer.wordpress.com/2016/11/11/wordpress-rest-api-on-wordpress-com/
    The WordPress REST API is available on WordPress.com with the following base URL: https://public-api.wordpress.com/wp/v2/
    """
    return r'https://public-api.wordpress.com/wp/v2/sites/{}/'.format(self.blog_url)
  def make_session(self) -> requests.Session:
    return make_session_without_credential()

  def get_pages_json(self, session: requests.Session = None):
    session = session if session is not None else self.make_session()
    response = self.get_pages()
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json; charset=UTF-8'
    assert response.headers['Access-Control-Allow-Headers'] == 'Authorization, Content-Type'
    # Access-Control-Allow-Headers sounds important but doesn't seem to matter:
    assert 'Authorization' not in response.request.headers
    assert 'Content-Type' not in response.request.headers
    assert len(response.request.headers) >= 4
    return response.json()
  def download_pages(self, directoryToSaveIn=None, session: requests.Session = None):
    session = session if session is not None else self.make_session()
    if not directoryToSaveIn:
      directoryToSaveIn = self.blog_url
    save_pages(self.get_pages_json(), directoryToSaveIn)


      


