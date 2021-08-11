from urtypes import RegistryType, RegistryItem

CRYPTO_BIP39 = RegistryType('crypto-bip39', 301)

class BIP39(RegistryItem):
	def __init__(self, words, lang):
		super().__init__()
		self.words = words
		self.lang = lang
  
	def __eq__(self, o):
		return self.words == o.words and self.lang == o.lang
  
	@classmethod
	def registry_type(cls):
		return CRYPTO_BIP39
	
	def to_data_item(self):
		map = {
			1: self.words
		}
		if self.lang is not None:
			map[2] = self.lang
		return map
	
	@classmethod
	def from_data_item(cls, item):
		map = cls.mapping(item)
		words = map[1]
		lang = map[2] if 2 in map else None
		return cls(words, lang)