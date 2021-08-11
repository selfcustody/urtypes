from urtypes import RegistryType, RegistryItem

CRYPTO_KEYPATH = RegistryType('crypto-keypath', 304)

class Keypath(RegistryItem):
	def __init__(self, components, source_fingerprint, depth):
		super().__init__()
		self.components = components
		self.source_fingerprint = source_fingerprint
		self.depth = depth
		  
	def __eq__(self, o):
		return self.components == o.components and self.source_fingerprint == o.source_fingerprint and self.depth == o.depth
  
	@classmethod
	def registry_type(cls):
		return CRYPTO_KEYPATH
	
	def path(self):
		if not self.components:
			return ''
		return '/'.join([('*' if component.wildcard else str(component.index)) + ('\'' if component.hardened else '') for component in self.components])
	
	def to_data_item(self):
		map = {}
		components = []
		for component in self.components:
			if component.wildcard:
				components.append([])
			else:
				components.append(component.index)
			components.append(component.hardened)
		map[1] = components
		if self.source_fingerprint is not None:
			map[2] = int.from_bytes(self.source_fingerprint, 'big')
		if self.depth is not None:
			map[3] = self.depth
		return map
	
	@classmethod
	def from_data_item(cls, item):
		map = cls.mapping(item)
		path_components = []
		components = map[1]
		if components:
			for i in range(0, len(components), 2):
				hardened = components[i + 1]
				path = components[i]
				if isinstance(path, int):
					path_components.append(PathComponent(path, hardened))
				else:
					path_components.append(PathComponent(None, hardened))
		source_fingerprint = map[2].to_bytes(4, 'big') if 2 in map else None
		depth = map[3] if 3 in map else None
		return cls(path_components, source_fingerprint, depth)

class PathComponent:
	def __init__(self, index, hardened):
		self.index = index
		self.hardened = hardened
		self.wildcard = self.index is None
		if self.index and self.index & 0x80000000 != 0:
			raise ValueError('Invalid index - most significant bit cannot be set')

	def __eq__(self, o):
		return self.index == o.index and self.hardened == o.hardened and self.wildcard == o.wildcard