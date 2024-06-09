APIs or bindings?
=================

This page describes both the **APIs** and the **bindings** provided by the *python-maec* library.

Overview
--------

The python-maec library provides APIs and utilities that aid in the creation, consumption, and processing of Structured Threat Information eXpression (MAEC) content. The APIs that drive much of the functionality of python-maec sit on top of a binding layer that acts as a direct connection between Python and the MAEC XML. Because both the APIs and the bindings allow for the creation and development of MAEC content, developers that are new to python-maec may not understand the differences between the two. This document aims to identify the purpose and uses of the APIs and bindings.

Bindings
--------

The python-maec library leverages machine generated XML-to-Python bindings for the creation and processing of MAEC content. These bindings are created using the `generateDS`_ utility and can be found under `maec.bindings`_ within the package hierarchy.

The MAEC bindings allow for a direct, complete mapping between Python classes and MAEC XML Schema data structures. That being said, it is possible (though not advised) to use only the MAEC bindings to create MAEC documents. However, because the code is generated from XML Schema without contextual knowledge of relationships or broader organizational/developmental schemes, it is often a cumbersome and laborious task to create even the simplest of MAEC documents.

Developers within the python-maec team felt that the binding code did not lend itself to rapid development or natural navigation of data, and so it was decided that a higher-level API should be created.

.. _generateDS: http://www.rexx.com/~dkuhlman/generateDS.html
.. _maec.bindings: https://github.com/MAECProject/python-maec/tree/master/maec/bindings

APIs
----

The python-maec APIs are classes and utilities that leverage the MAEC bindings for the creation and processing of MAEC content. The APIs are designed to behave more naturally when working with MAEC content, allowing developers to conceptualize and interact with MAEC documents as pure Python objects and not XML Schema objects.

The APIs provide validation of inputs, multiple input and output formats, more Pythonic access of data structure internals and interaction with classes, and better interpretation of a developers intent through datatype coercion and implicit instantiation.

.. note::

	The python-maec APIs are under constant development. Our goal is to provide full API coverage of the MAEC data structures, but not all structures are exposed via the APIs yet. Please refer to the :doc:`../api/index` for API coverage details.
	
Brevity Wins
------------

The two code examples show the difference in creating and printing a simple MAEC document consisting of only a MAEC Bundle with a single Malware Action using the python-maec and python-cybox bindings. Both examples will produce the same MAEC XML!

.. container:: side-by-side

	.. container:: 

		**API Example**

		.. include:: api_snippet.rst

	.. container:: 

		**Binding Example**

		.. include:: binding_snippet.rst

Feedback
--------

If there is a problem with the APIs or bindings, or if there is functionality missing from the APIs that forces the use of the bindings, let us know in the `python-maec issue tracker`_

.. _python-maec issue tracker: https://github.com/MAECProject/python-maec/issues
