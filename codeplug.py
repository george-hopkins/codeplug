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
from OpenSSL.crypto import load_pkcs12


_CP1252_BESTFIT = {
    128: 8364,
    130: 8218,
    131: 402,
    132: 8222,
    133: 8230,
    134: 8224,
    135: 8225,
    136: 710,
    137: 8240,
    138: 352,
    139: 8249,
    140: 338,
    142: 381,
    145: 8216,
    146: 8217,
    147: 8220,
    148: 8221,
    149: 8226,
    150: 8211,
    151: 8212,
    152: 732,
    153: 8482,
    154: 353,
    155: 8250,
    156: 339,
    158: 382,
    159: 376,
}


_CP1252_BESTFIT_INVERSE = {c: u for u, c in _CP1252_BESTFIT.items()}


_UUID_TO_ARCHIVE_TYPE = {
    'AF5DAB63F4FC4926BB9000A6F18AF3DC': 'BAHAMA',
    '0571AFE244664F999A96B020E82DC69C': 'GEMSTONE',
    '0C78E1B906C54D3A8F264CE5C4F0B9DF': 'GEMSTONE',
    'C52A3D4953FE469D8E11F05B143E8C56': 'GEMSTONE',
    'EBCCE9BF33B14896B5C2E7E3AA19AF0F': 'GEMSTONE',
    '9F6C2442C375421981A8987115FC9ADE': 'MALTA',
    'D105ADD323864E539B513A65076458D3': 'MATRIX',
    '0C0D6EE58204FBDEBB8860C631AB465A': 'PARADISE_LIGHT',
    '1EC82E1A4AE2B4F1A8AC27E8039CB7E4': 'PARADISE_LIGHT',
    'C4FC39D8DEF24B779D1CB719AF26A269': 'PARADISE_LIGHT',
    '06CE7B7163C0456A845A6E13421F0AE4': 'PHOENIX',
    '106F58B631044D63B41F0C0D7720758D': 'REUNION',
}


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


def _encode_xml_chars(data: bytes) -> bytes:
    """Encode control characters"""
    result = []
    for c in data:
        if c < 0x20 and c not in [0x09, 0x0a, 0x0d]:
            result += '&#x{:X};'.format(c).encode()
        else:
            result.append(c)
    return bytes(result)


def _decode_xml_chars(data: bytes) -> bytes:
    """Decode control characters"""
    for c in range(0, 0x20):
        if c in [0x09, 0x0a, 0x0d]:
            continue
        data = data.replace('&#x{:X};'.format(c).encode(), bytes([c]))
    return data


def _encode_ascii_binary(data: bytes) -> str:
    """Map non-printable characters to a Unicode Private Use Area"""
    result = []
    for c in data:
        if (c >= 0x20 and c < 0x7f) or c == 0x0a:
            result.append(c)
        else:
            result += chr(0xe000 | c).encode('utf-8')
    return bytes(result).decode()


def _decode_ascii_binary(data: str) -> bytes:
    """Map non-printable characters back from the Unicode Private Use Area"""
    result = []
    for c in data:
        p = ord(c)
        if p >= 0xe000 and p <= 0xe0ff:
            result.append(p & 0xff)
        else:
            result.append(p)
    return bytes(result)


def _decode_xml_privateuse(data: bytes) -> bytes:
    """Decode Unicode characters of the Unicode Private Use Area"""
    result = []
    for c in data:
        p = ord(c)
        if p >= 0xe000 and p <= 0xe0ff:
            result.append(p & 0xff)
        else:
            result.append(p)
    return bytes(result)


def _encode_cp1252_bestfit(data: bytes) -> bytes:
    """Map CP-1252 codepoints to Unicode"""
    result = b''
    for c in data:
        result += chr(_CP1252_BESTFIT.get(c, c)).encode('utf-8')
    return result


def _decode_cp1252_bestfit(data: bytes) -> bytes:
    """Interpret bytes as Unicode codepoints and map them back to CP-1252"""
    result = []
    for c in data:
        p = ord(c)
        result.append(_CP1252_BESTFIT_INVERSE.get(p, p))
    return bytes(result)


def decode(data, key, iv):
    backend = default_backend()

    doc = etree.fromstring(_encode_ascii_binary(_decode_xml_chars(data.strip())))
    archive_type = doc.get('TYPE')
    archive_content = doc.xpath('RADIO')[0].text
    if archive_type == 'GEMSTONE':
        encrypted = base64.b64decode(archive_content)
    elif archive_type == 'MATRIX':
        encrypted = _decode_cp1252_bestfit(_decode_ascii_binary(archive_content).decode())
    else:
        raise Exception('Unsupported archive type: {}'.format(archive_type))

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

    return archive_type, payload


def build(archive_type, payload, signing_key, key, iv, backend):
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
    doc.set('TYPE', archive_type)
    node = etree.SubElement(doc, 'RADIO')
    node.set('VERSION', '1')
    if archive_type == 'GEMSTONE':
        node.set('ENCODING', 'Base64')
        node.text = base64.b64encode(encrypted)
    elif archive_type == 'MATRIX':
        node.text = _encode_ascii_binary(_encode_cp1252_bestfit(encrypted))
    else:
        raise Exception('Unsupported archive type: {}'.format(archive_type))

    xml = etree.tostring(doc, encoding='utf-8')

    return _encode_xml_chars(_decode_ascii_binary(xml.decode()))


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

    archive_type, result = decode(data, base64.b64decode(config['key']), base64.b64decode(config['iv']))

    xml = etree.fromstring(result)

    output_path = args.output or args.file + '.xml'
    with open(output_path, 'wb') as f:
        f.write(etree.tostring(xml, pretty_print=True))

    print('Decoded {} archive to {}'.format(archive_type, output_path))


def _build_cmd(args):
    config = _read_config(args.config)

    backend = default_backend()

    doc = etree.parse(args.file)

    uuid = doc.xpath('//CS_FWID')[0].text
    archive_type = _UUID_TO_ARCHIVE_TYPE[uuid]

    payload = etree.tostring(doc, encoding='utf-8')

    if 'signing_password' in config:
        signing_key = load_pkcs12(base64.b64decode(config['signing_key']), base64.b64decode(config['signing_password'])).get_privatekey().to_cryptography_key()
    else:
        signing_key = load_pem_private_key(config['signing_key'].encode('ascii'), password=None, backend=backend)

    result = build(archive_type, payload, signing_key, base64.b64decode(config['key']), base64.b64decode(config['iv']), backend)

    output_path = args.output or args.file + '.ctb'
    with open(output_path, 'wb') as f:
        f.write(result)

    print('Built {} archive in {}'.format(archive_type, output_path))


def main():
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('-c', help='load configuration from the specified file', dest='config')
    parent_parser.add_argument('-o', help='output result to the specified file', dest='output')
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
