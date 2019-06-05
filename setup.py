import setuptools
import os.path

import sphinx.application
import sphinx.setup_command

# To install this package: $ pip install --requirement ./requirements.txt --editable .
# To run the tests: $ python setup.py test or pytest
# To run the doctests: $ python setup.py doctest
# To build the documentation: $ python setup.py build_sphinx

# https://dankeder.com/posts/adding-custom-commands-to-setup-py/
class Doctest(setuptools.Command):
  description = 'Run doctests with Sphinx'
  user_options = []

  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def run(self):
    sphinx.application.Sphinx('./doc/source', # source directory
                     './doc/source', # directory containing conf.py
                     './doc/build', # output directory
                     './doc/build/doctrees', # doctree directory
                     'doctest' # finally, specify the doctest builder
                     ).build()


projectName = 'wordpress-rest-api-v2'
description='Package for interacting with WordPress.'

packageData = dict()
packageData[projectName] = ['resources/*.json']

versionString = '0.1'
releaseString = '0.1.0'

def getREADMEforDescription(readmePath=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'README.md')):
  """Use the Markdown from the file for the package's long_description.
  long_description_content_type should be 'text/markdown' if the README is Markdown.
  """
  try:
    with open(readmePath) as readme:
      return '\n' + readme.read()
  except FileNotFoundError:
    return description

if __name__ == '__main__':
  setuptools.setup(name=projectName,
      version=versionString,
      description=description,
      long_description=getREADMEforDescription(),
      long_description_content_type='text/markdown',
      license='MIT',
      command_options={
        'build_sphinx': {
            'project': ('setup.py', projectName),
            'version': ('setup.py', versionString),
            'release': ('setup.py', releaseString),
            'source_dir': ('setup.py', os.path.join('doc', 'source'))}},
      packages=setuptools.find_packages('src'),
      package_dir={'': 'src'},
      package_data=packageData,
      entry_points={
        'console_scripts': [
          'upload_to_multisite = wordpress.api:upload_to_multisite',
        ],
      },
      install_requires=[
          'pytest',
      ],
      setup_requires=[
              'pytest-runner',
      ],
      tests_require=['pytest'],
      cmdclass={
        'doctest': Doctest,
      },
      zip_safe=True)
