from urtypes import RegistryType, RegistryItem
from .output import Output

CRYPTO_ACCOUNT = RegistryType('crypto-account', 311)

class Account(RegistryItem):
	def __init__(self, master_fingerprint, output_descriptors):
		super().__init__()
		self.master_fingerprint = master_fingerprint
		self.output_descriptors = output_descriptors
		
	def __eq__(self, o):
		return self.master_fingerprint == o.master_fingerprint and self.output_descriptors == o.output_descriptors
  
	@classmethod
	def registry_type(cls):
		return CRYPTO_ACCOUNT
	
	def to_data_item(self):
		map = {}
		if self.master_fingerprint is not None:
			map[1] = int.from_bytes(self.master_fingerprint, 'big')
		if self.output_descriptors is not None:
			map[2] = [descriptor.to_data_item() for descriptor in self.output_descriptors]
		return map
	
	@classmethod
	def from_data_item(cls, item):
		map = cls.mapping(item)
		master_fingerprint = map[1].to_bytes(4, 'big') if 1 in map else None
		outputs = [Output.from_data_item(item) for item in map[2]] if 2 in map else None
		return cls(master_fingerprint, outputs)