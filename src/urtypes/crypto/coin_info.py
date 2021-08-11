from urtypes import RegistryType, RegistryItem

CRYPTO_COIN_INFO = RegistryType('crypto-coin-info', 305)

class CoinInfo(RegistryItem):
	def __init__(self, type, network):
		super().__init__()
		self.type = type
		self.network = network
		
	def __eq__(self, o):
		return self.type == o.type and self.network == o.network
  
	@classmethod
	def registry_type(cls):
		return CRYPTO_COIN_INFO
	
	def to_data_item(self):
		map = {}
		if self.type is not None:
			map[1] = self.type
		if self.network is not None:
			map[2] = self.network
		return map
	
	@classmethod
	def from_data_item(cls, item):
		map = cls.mapping(item)
		type = map[1] if 1 in map else None
		network = map[2] if 2 in map else None
		return cls(type, network)