import binascii
from unittest import TestCase
from urtypes.crypto import ECKey

class ECKeyTestCase(TestCase):
	def table(self):
		return [
			{
				'test': 'Example/Test Vector 1 (private key)',
				'item': ECKey(
                    binascii.unhexlify('8c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa'), 
                    None, 
                    True
                ),
				'cbor': binascii.unhexlify('a202f50358208c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa'),
			},
			{
				'test': 'Example/Test Vector 1 (public key)',
				'item': ECKey(
                    binascii.unhexlify('03bec5163df25d8703150c3a1804eac7d615bb212b7cc9d7ff937aa8bd1c494b7f'), 
                    None, 
                    None
                ),
				'cbor': binascii.unhexlify('a103582103bec5163df25d8703150c3a1804eac7d615bb212b7cc9d7ff937aa8bd1c494b7f'),
			}
		]

	def test_from_cbor(self):
		for row in self.table():
			self.assertEqual(ECKey.from_cbor(row['cbor']), row['item'])

	def test_to_cbor(self):
		for row in self.table():
			self.assertEqual(row['item'].to_cbor(), row['cbor'])