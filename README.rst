codeplug
========

.. image:: https://img.shields.io/travis/george-hopkins/codeplug/master.svg
  :target: https://travis-ci.org/george-hopkins/codeplug
  :alt: Build Status
.. image:: https://img.shields.io/pypi/v/codeplug.svg
  :target: https://pypi.python.org/pypi/codeplug/
  :alt: Latest Version

Read and write Motorola Codeplugs (.ctb) from the commandline.


Getting Started
---------------

::

  pip install codeplug
  # set the keys in codeplug.cfg
  codeplug decode yourfile.ctb
  # modify yourfile.ctb.xml
  codeplug build yourfile.ctb.xml

**Note:** If you own a copy of MOTOTRBO CPS, you can use codeplug-prepare_ to extract the keys.

.. _codeplug-prepare: https://github.com/george-hopkins/codeplug-prepare
