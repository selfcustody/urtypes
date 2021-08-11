from urtypes import RegistryType, RegistryItem

BYTES = RegistryType('bytes', None)

class Bytes(RegistryItem):
	def __init__(self, data):
		super().__init__()
		self.data = data
		
	def __eq__(self, o):
		return self.data == o.data
 
	@classmethod
	def registry_type(cls):
		return BYTES
	
	def to_data_item(self):
		return self.data

	@classmethod
	def from_data_item(cls, item):
		return cls(cls.mapping(item))