|Build_Status| |Coverage| |Version| |Downloads_Badge|

cti-python-stix2
================

This is the MISP core team STIX2 library forked from the `OASIS TC Open Repository <https://www.oasis-open.org/resources/open-repositories/>`__.

This repository provides Python APIs for serializing and de-serializing STIX2
JSON content, along with higher-level APIs for common tasks, including data
markings, versioning, and for resolving STIX IDs across multiple data sources.

For more information, see `the documentation <https://stix2.readthedocs.io/>`__ on ReadTheDocs.

Installation
------------

Install with `pip <https://pip.pypa.io/en/stable/>`__:

.. code-block:: bash

  $ pip install misp-lib-stix2

Note: The library requires Python 3.7+.

PyPI module: `misp-lib-stix2 <https://pypi.org/project/misp-lib-stix2/>`__.

Usage
-----

To create a STIX object, provide keyword arguments to the type's constructor.
Certain required attributes of all objects, such as ``type`` or ``id``,  will
be set automatically if not provided as keyword arguments.

.. code-block:: python

    from stix2 import Indicator

    indicator = Indicator(name="File hash for malware variant",
                          indicator_types=["malicious-activity"],
                          pattern_type="stix",
                          pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']")

To parse a STIX JSON string into a Python STIX object, use ``parse()``. To serialize a STIX object, use ``serialize()``:

.. code-block:: python

    from stix2 import parse

    indicator = parse("""{
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--dbcbd659-c927-4f9a-994f-0a2632274394",
        "created": "2017-09-26T23:33:39.829Z",
        "modified": "2017-09-26T23:33:39.829Z",
        "name": "File hash for malware variant",
        "indicator_types": [
            "malicious-activity"
        ],
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "pattern": "[file:hashes.md5 ='d41d8cd98f00b204e9800998ecf8427e']",
        "valid_from": "2017-09-26T23:33:39.829952Z"
    }""")

    print(indicator.serialize(pretty=True))

For more in-depth documentation, please see `https://stix2.readthedocs.io/ <https://stix2.readthedocs.io/>`__.

STIX 2 Technical Specification Support
--------------------------------------

This version of cti-python-stix2 brings support to `STIX Version 2.1 <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>`__
published on 10 June 2021 currently at the Committee Specification (CS) 03 level, also know as the "OASIS Standard".

The stix2 Python library supports multiple versions of the STIX 2 Technical
Specification. The library will be updated to support new Committee
Specification Drafts (CSDs) as they are released, but modules for these
versions must be imported manually until the CSD reaches CS level. In new
major releases of stix2 the ``import stix2`` implicit import statement
will be updated to automatically load the STIX Objects equivalent to the most
recently supported CS. Please see the `library documentation <https://stix2.readthedocs.io/en/latest/guide/ts_support.html>`__
for details.

Contributing
------------

This is the MISP core team STIX2 library forked from the `OASIS TC Open Repository <https://www.oasis-open.org/resources/open-repositories/>`__.

The contributing rules of this repository is the MISP standard rules bound to the `Developer Certificate of Origin <https://www.misp-project.org/license/>`__.

If you want to contribute, no need to sign a CLA.


.. |Build_Status| image:: https://github.com/misp/cti-python-stix2/workflows/cti-python-stix2%20test%20harness/badge.svg
   :target: https://github.com/misp/cti-python-stix2/actions?query=workflow%3A%22cti-python-stix2+test+harness%22
   :alt: Build Status
.. |Coverage| image:: https://codecov.io/gh/misp/cti-python-stix2/branch/main/graph/badge.svg
   :target: https://codecov.io/gh/misp/cti-python-stix2
   :alt: Coverage
.. |Version| image:: https://img.shields.io/pypi/v/misp-lib-stix2.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/misp-lib-stix2/
   :alt: Version
.. |Downloads_Badge| image:: https://img.shields.io/pypi/dm/misp-lib-stix2.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/misp-lib-stix2/
   :alt: Downloads
