import binascii
from urtypes import RegistryType, RegistryItem

CRYPTO_ECKEY = RegistryType('crypto-eckey', 306)

class ECKey(RegistryItem):
	def __init__(self, data, curve, private_key):
		super().__init__()
		self.data = data
		self.curve = curve
		self.private_key = private_key
		
	def __eq__(self, o):
		return self.data == o.data and self.curve == o.curve and self.private_key == o.private_key
  
	@classmethod
	def registry_type(cls):
		return CRYPTO_ECKEY
	
	def to_data_item(self):
		map = {}
		if self.curve is not None:
			map[1] = self.curve
		if self.private_key is not None:
			map[2] = self.private_key
		map[3] = self.data
		return map
	
	@classmethod
	def from_data_item(cls, item):
		map = cls.mapping(item)
		data = map[3]
		curve = map[1] if 1 in map else None
		private_key = map[2] if 2 in map else None
		return cls(data, curve, private_key)

	def descriptor_key(self):
		return binascii.hexlify(self.data).decode()