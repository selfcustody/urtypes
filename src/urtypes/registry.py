import io
from urtypes.cbor import decoder, encoder, DataItem

class RegistryType:
	def __init__(self, type, tag):
		self.type = type
		self.tag = tag
  
class RegistryItem:
	@classmethod
	def registry_type(cls):
		raise NotImplementedError()

	@classmethod
	def mapping(cls, item):  
		if isinstance(item, DataItem):
			registry_type = cls.registry_type()
			if (registry_type is None and item.tag is None) or (registry_type is not None and registry_type.tag == item.tag):
				return item.map
		return item

	@classmethod
	def from_data_item(cls, item):
		raise NotImplementedError()

	def to_data_item(self):
		raise NotImplementedError()
  
	@classmethod
	def from_cbor(cls, cbor_payload):
		cbor_decoder = decoder.Decoder(io.BytesIO(cbor_payload))
		return cls.from_data_item(cbor_decoder.decode())
	
	def to_cbor(self):
		cbor_encoder = encoder.Encoder(io.BytesIO())
		cbor_encoder.encode(self.to_data_item())
		v = cbor_encoder.output.getvalue()
		cbor_encoder.output.close()
		return v
