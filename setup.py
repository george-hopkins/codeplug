from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='codeplug',
    version='0.2.0',

    description='codeplug decoder and builder for Motorola radios',
    long_description=long_description,
    url='https://github.com/george-hopkins/codeplug',

    author='George Hopkins',
    author_email='george-hopkins@null.net',

    license='MIT',

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Telecommunications Industry',
        'Topic :: Communications :: Ham Radio',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],

    keywords='motorola mototrbo cps ctb codeplug dmr',

    py_modules=['codeplug'],

    install_requires=[
        'cryptography>=1.6',
        'lxml>=3',
        'pyOpenSSL>=17',
    ],
    extras_require={
        'dev': [],
        'test': [],
    },

    entry_points={
        'console_scripts': [
            'codeplug=codeplug:main',
        ],
    },
)
