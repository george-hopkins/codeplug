from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='codeplug',
    version='0.1.0',

    description='codeplug decoder and builder for Motorola radios',
    long_description=long_description,
    url='https://github.com/george-hopkins/codeplug',

    author='George Hopkins',
    author_email='george-hopkins@null.net',

    license='MIT',

    classifiers=[
        'Development Status :: 3 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Telecommunications Industry',
        'Topic :: Communications :: Ham Radio',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    keywords='motorola mototrbo cps ctb codeplug dmr',

    packages=find_packages(exclude=['tests']),

    install_requires=[
        'cryptography>=1.6',
        'lxml>=3',
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
