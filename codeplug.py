import argparse
import base64
import binascii
import configparser
import os
import sys
import zlib
from lxml import etree
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def _int_to_bytes(number):
    return number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')


def _key_from_xml(node, backend):
    mod = int.from_bytes(base64.b64decode(node.xpath('RSAKeyValue/Modulus')[0].text), byteorder='big')
    exp = int.from_bytes(base64.b64decode(node.xpath('RSAKeyValue/Exponent')[0].text), byteorder='big')
    return RSAPublicNumbers(exp, mod).public_key(backend)


def _key_to_xml(key, root):
    numbers = key.public_numbers()
    node = etree.SubElement(root, 'RSAKeyValue')
    etree.SubElement(node, 'Modulus').text = base64.b64encode(_int_to_bytes(numbers.n))
    etree.SubElement(node, 'Exponent').text = base64.b64encode(_int_to_bytes(numbers.e))


def decode(data, key, iv):
    backend = default_backend()

    doc = etree.fromstring(data)
    node = doc.xpath('/ARCHIVE/RADIO')[0]
    encrypted = base64.b64decode(node.text)

    decryptor = Cipher(AES(key), CBC(iv), backend=backend).decryptor()
    compressed = decryptor.update(encrypted) + decryptor.finalize()

    signed = zlib.decompress(compressed, 16 + zlib.MAX_WBITS)
    if signed[:3] != b'\xef\xbb\xbf':
        raise Exception('Invalid header')

    signature_pos = signed.rfind(b'<SIGNATURE>')
    payload = signed[3:signature_pos]
    signature = etree.fromstring(signed[signature_pos:])

    digest = bytes.fromhex(signature.xpath('DIGEST')[0].text)
    key = _key_from_xml(signature, backend)
    key.verify(digest, payload.decode('utf-8').encode('utf-16-le'), PKCS1v15(), SHA1())

    return payload


def build(payload, signing_key, key, iv, backend):
    backend = signing_key._backend

    signature = signing_key.sign(payload.decode('utf-8').encode('utf-16-le'), PKCS1v15(), SHA1())

    sign_doc = etree.Element('SIGNATURE')
    etree.SubElement(sign_doc, 'VERSION').text = '1.0'
    etree.SubElement(sign_doc, 'DIGEST').text = binascii.hexlify(signature).decode().upper()
    _key_to_xml(signing_key.public_key(), sign_doc)

    signed = b'\xef\xbb\xbf' + payload + etree.tostring(sign_doc)

    compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    compressed = compressor.compress(signed) + compressor.flush()

    padder = PKCS7(len(iv) * 8).padder()
    padded = padder.update(compressed) + padder.finalize()

    encryptor = Cipher(AES(key), CBC(iv), backend=backend).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    doc = etree.Element('ARCHIVE')
    doc.set('TYPE', 'GEMSTONE')
    node = etree.SubElement(doc, 'RADIO')
    node.set('VERSION', '1')
    node.set('ENCODING', 'Base64')
    node.text = base64.b64encode(encrypted)

    return etree.tostring(doc)


def _read_config(filename):
    config = configparser.ConfigParser()
    config['codeplug'] = {}

    if filename:
        config.read_file(open(filename, 'r'))
    elif os.path.isfile('codeplug.cfg'):
        config.read_file(open('codeplug.cfg', 'r'))

    for key, value in os.environ.items():
        if key.startswith('CODEPLUG_'):
            config['codeplug'][key[9:].lower()] = value

    if 'key' not in config['codeplug']:
        raise Exception('Invalid configuration')

    return config['codeplug']


def _decode_cmd(args):
    config = _read_config(args.config)

    with open(args.file, 'rb') as f:
        data = f.read()

    result = decode(data, base64.b64decode(config['key']), base64.b64decode(config['iv']))

    xml = etree.fromstring(result)

    with open(args.output or args.file + '.xml', 'wb') as f:
        f.write(etree.tostring(xml, pretty_print=True))


def _build_cmd(args):
    config = _read_config(args.config)

    backend = default_backend()

    payload = etree.tostring(etree.parse(args.file))

    signing_key = load_pem_private_key(config['signing_key'].encode('ascii'), password=None, backend=backend)

    result = build(payload, signing_key, base64.b64decode(config['key']), base64.b64decode(config['iv']), backend)

    with open(args.output or args.file + '.ctb', 'wb') as f:
        f.write(result)


def main():
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('-c', dest='config')
    parent_parser.add_argument('-o', dest='output')
    parent_parser.add_argument('file')

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True

    parser_decode = subparsers.add_parser('decode', parents=[parent_parser])
    parser_decode.set_defaults(func=_decode_cmd)

    parser_build = subparsers.add_parser('build', parents=[parent_parser])
    parser_build.set_defaults(func=_build_cmd)

    args = parser.parse_args()
    return args.func(args)


if __name__ == '__main__':
    main()
