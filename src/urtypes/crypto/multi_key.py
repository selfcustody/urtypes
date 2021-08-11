from urtypes import RegistryItem
from urtypes.cbor import DataItem
from .hd_key import HDKey, CRYPTO_HDKEY
from .ec_key import ECKey, CRYPTO_ECKEY

class MultiKey(RegistryItem):
	def __init__(self, threshold, ec_keys, hd_keys):
		super().__init__()
		self.threshold = threshold
		self.ec_keys = ec_keys
		self.hd_keys = hd_keys
		  
	def __eq__(self, o):
		return self.threshold == o.threshold and self.ec_keys == o.ec_keys and self.hd_keys == o.hd_keys
  
	@classmethod
	def registry_type(cls):
		return None
	
	def to_data_item(self):
		map = {}
		map[1] = self.threshold
		combined_keys = self.ec_keys[:] + self.hd_keys[:]
		keys = []
		for key in combined_keys:
			keys.append(DataItem(key.registry_type().tag, key.to_data_item()))
		map[2] = keys
		return map      
	
	@classmethod
	def from_data_item(cls, item):
		map = item.map
		threshold = map[1]
		keys = map[2]
		ec_keys = []
		hd_keys = []
		for key in keys:
			if key.tag == CRYPTO_HDKEY.tag:
				hd_keys.append(HDKey.from_data_item(key))
			elif key.tag == CRYPTO_ECKEY.tag:
				ec_keys.append(ECKey.from_data_item(key))
		return cls(threshold, ec_keys, hd_keys)