mixbox
======

A library of common code leveraged by python-cybox, python-maec, and python-stix.

|travis_badge| |landscape_io_badge| |version_badge|

.. |travis_badge| image:: https://api.travis-ci.org/CybOXProject/mixbox.svg?branch=master
   :target: https://travis-ci.org/CybOXProject/mixbox
   :alt: Build Status
.. |landscape_io_badge| image:: https://landscape.io/github/CybOXProject/mixbox/master/landscape.svg?style=flat
   :target: https://landscape.io/github/CybOXProject/mixbox/master
   :alt: Code Health
.. |version_badge| image:: https://img.shields.io/pypi/v/mixbox.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/mixbox/
   :alt: Version


Developing
----------

To set up an environment to develop `mixbox`:

.. code:: bash

   # Create a new virtualenv
   $ mkvirtualenv mixbox

   # Change to this directory and install requirements
   $ cd /path/to/mixbox
   $ pip install -r requirements.txt

   # Install python-cybox, python-maec, and python-stix in "develop" mode.
   $ pip install -e /path/to/python-cybox
   $ pip install -e /path/to/python-maec
   $ pip install -e /path/to/python-stix


Then you can make changes to the `mixbox` library and ensure the test cases for
the corresponding projects continue to pass (using `tox` or `nosetests`).

Releasing
---------

.. code:: bash

    $ bumpversion patch
    $ git push origin master --tags
    $ rm dist/*
    $ python setup.py sdist bdist_wheel
    $ twine upload dist/*
