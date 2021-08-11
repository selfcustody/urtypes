import binascii
from unittest import TestCase
from urtypes.crypto import BIP39

class BIP39TestCase(TestCase):
	def table(self):
		return [
			{
				'test': 'Example/Test Vector (16 byte (128-bit) seed, encoded as BIP39)',
				'item': BIP39(
                    ['shield', 'group', 'erode', 'awake', 'lock', 'sausage', 'cash', 'glare', 'wave', 'crew', 'flame', 'glove'],
                    'en'
                ),
				'cbor': binascii.unhexlify('a2018c66736869656c646567726f75706565726f6465656177616b65646c6f636b6773617573616765646361736865676c6172656477617665646372657765666c616d6565676c6f76650262656e'),
			}
		]

	def test_from_cbor(self):
		for row in self.table():
			self.assertEqual(BIP39.from_cbor(row['cbor']), row['item'])

	def test_to_cbor(self):
		for row in self.table():
			self.assertEqual(row['item'].to_cbor(), row['cbor'])