codeplug
========

Read and write Motorola Codeplugs (.ctb) from the commandline.


Getting Started
---------------

::

  pip install codeplug
  export CTB_KEY='...'
  export CTB_IV='...'
  codeplug decode yourfile.ctb
  # modify yourfile.ctb.xml
  codeplug build yourfile.ctb.xml yourprivkey.pem

**Note:** If you own a copy of MOTOTRBO CPS, you can use codeplug-prepare_ to extract the keys.

.. _codeplug-prepare: https://github.com/george-hopkins/codeplug-prepare
