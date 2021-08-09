import binascii
import hashlib
import io
from .cbor import decoder, encoder, data

def polymod(c, val):
	c0 = c >> 35
	c = ((c & 0x7ffffffff) << 5) ^ val
	if c0 & 1: c ^= 0xf5dee51989
	if c0 & 2: c ^= 0xa9fdca3312
	if c0 & 4: c ^= 0x1bab10e32d
	if c0 & 8: c ^= 0x3706b1677a
	if c0 & 16: c ^= 0x644d626ffd
	return c

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def descriptor_checksum(descriptor):
	c = 1
	cls = 0
	clscount = 0
	for ch in descriptor:
		pos = INPUT_CHARSET.find(ch)
		if pos == -1:
			return ''
		c = polymod(c, pos & 31)
		cls = cls * 3 + (pos >> 5)
		clscount += 1
		if (clscount == 3):
			c = polymod(c, cls)
			cls = 0
			clscount = 0
	if clscount > 0: c = polymod(c, cls)
	for _ in range(8):
		c = polymod(c, 0)
	c ^= 1
	checksum = ''
	for i in range(8):
		checksum += CHECKSUM_CHARSET[(c >> (5 * (7 - i))) & 31]
	return checksum;

B58_DIGITS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def double_sha256(msg):
	"""sha256(sha256(msg)) -> bytes"""
	return hashlib.sha256(hashlib.sha256(msg).digest()).digest()

def encode(b):
	"""Encode bytes to a base58-encoded string"""

	# Convert big-endian bytes to integer
	n = int("0x0" + binascii.hexlify(b).decode("utf8"), 16)

	# Divide that integer into bas58
	res = []
	while n > 0:
		n, r = divmod(n, 58)
		res.append(B58_DIGITS[r])
	res = "".join(res[::-1])

	pad = 0
	for c in b:
		if c == 0:
			pad += 1
		else:
			break
	return B58_DIGITS[0] * pad + res

def encode_check(b):
	"""Encode bytes to a base58-encoded string with a checksum"""
	return encode(b + double_sha256(b)[0:4])

class RegistryType:
	def __init__(self, type, tag):
		self.type = type
		self.tag = tag
		
BYTES            = RegistryType('bytes', None),
CRYPTO_BIP39     = RegistryType('crypto-bip39', 301)
CRYPTO_HDKEY     = RegistryType('crypto-hdkey', 303)
CRYPTO_KEYPATH   = RegistryType('crypto-keypath', 304)
CRYPTO_COIN_INFO = RegistryType('crypto-coin-info', 305)
CRYPTO_ECKEY     = RegistryType('crypto-eckey', 306)
CRYPTO_OUTPUT    = RegistryType('crypto-output', 308)
CRYPTO_PSBT      = RegistryType('crypto-psbt', 310)
CRYPTO_ACCOUNT   = RegistryType('crypto-account', 311)

TAGS = [301, 303, 304, 305, 306, 307, 308, 310, 311, 400, 401, 402, 403, 404, 405, 406, 407, 408]

class RegistryItem:
	@classmethod
	def from_cbor(cls, cbor_payload):
		# Prepend the tag of the class if it isn't already there so the decoder can parse properly
		if not binascii.hexlify(cbor_payload).decode().upper().startswith('D9') and cls != Bytes:
			tag_hex = hex(cls.registry_type().tag)[2:].upper()
			tag_hex = '0' * (4 - len(tag_hex)) + tag_hex
			cbor_payload = binascii.unhexlify('D9' + tag_hex) + cbor_payload
		cbor_decoder = decoder.StandardDecoder(io.BytesIO(cbor_payload), dict([(tag, DataItem) for tag in TAGS]))
		decoded = cbor_decoder.decode()
		if isinstance(decoded, DataItem):
			return cls.from_data_item(decoded)
		return cls(decoded)
	
	def to_cbor(self):
		cbor_encoder = encoder.Encoder(io.BytesIO())
		item = self.to_data_item()
		# Encode the map / inner data item so that the outer tag isn't included
		cbor_encoder.encode(item.map)
		v = cbor_encoder.output.getvalue()
		cbor_encoder.output.close()
		return v
	
	@staticmethod
	def registry_type(cls):
		raise NotImplementedError()
	
	def to_data_item(self):
		raise NotImplementedError()
		
class ScriptExpression:
	def __init__(self, tag, expression):
		self.tag = tag
		self.expression = expression

ADDRESS                 = ScriptExpression(307, 'addr')
SCRIPT_HASH             = ScriptExpression(400, 'sh')
WITNESS_SCRIPT_HASH     = ScriptExpression(401, 'wsh')
PUBLIC_KEY              = ScriptExpression(402, 'pk')
PUBLIC_KEY_HASH         = ScriptExpression(403, 'pkh')
WITNESS_PUBLIC_KEY_HASH = ScriptExpression(404, 'wpkh')
COMBO                   = ScriptExpression(405, 'combo')
MULTISIG                = ScriptExpression(406, 'multi')
SORTED_MULTISIG         = ScriptExpression(407, 'sortedmulti')
RAW_SCRIPT              = ScriptExpression(408, 'raw')
	
script_expressions_by_tag = {
	307: ADDRESS,
	400: SCRIPT_HASH,
	401: WITNESS_SCRIPT_HASH,
	402: PUBLIC_KEY,
	403: PUBLIC_KEY_HASH,
	404: WITNESS_PUBLIC_KEY_HASH,
	405: COMBO,
	406: MULTISIG,
	407: SORTED_MULTISIG,
	408: RAW_SCRIPT
}

HARDENED_BIT = 0x80000000

class PathComponent:
	def __init__(self, index, hardened):
		self.index = index
		self.hardened = hardened
		self.wildcard = self.index is None
		if self.index and self.index & HARDENED_BIT != 0:
			raise ValueError('Invalid index - most significant bit cannot be set')

class DataItem(data.Tagging):
	def __init__(self, tag, map):
		super().__init__(tag, encoder.Mapping(map))
		self.tag = tag
		self.map = map
	  
class Bytes(RegistryItem):
	def __init__(self, data):
		super().__init__()
		self.data = data
		
	@classmethod
	def registry_type(cls):
		return BYTES
	
	def to_data_item(self):
		return DataItem(self.registry_type().tag, self.data)

	@classmethod
	def from_data_item(cls, item):
		return cls(item.map)
	
class CryptoAccount(RegistryItem):
	def __init__(self, master_fingerprint, output_descriptors):
		super().__init__()
		self.master_fingerprint = master_fingerprint
		self.output_descriptors = output_descriptors
		
	@classmethod
	def registry_type(cls):
		return CRYPTO_ACCOUNT
	
	def to_data_item(self):
		map = {}
		if self.master_fingerprint:
			map[1] = int.from_bytes(self.master_fingerprint, 'big')
		if self.output_descriptors:
			map[2] = [descriptor.to_data_item() for descriptor in self.output_descriptors]
		return DataItem(self.registry_type().tag, map)
	
	@classmethod
	def from_data_item(cls, item):
		map = item.map
		master_fingerprint = bytes(4)
		if 1 in map:
			master_fingerprint = map[1].to_bytes(4, 'big')
		outputs = []
		if 2 in map:
			outputs = [CryptoOutput.from_data_item(item) for item in map[2]]
		return cls(master_fingerprint, outputs)
	
class CryptoCoinInfo(RegistryItem):
	def __init__(self, type=0, network=0):
		super().__init__()
		self.type = type
		self.network = network
		
	@classmethod
	def registry_type(cls):
		return CRYPTO_COIN_INFO
	
	def to_data_item(self):
		map = {
			1: self.type,
			2: self.network
		}
		return DataItem(self.registry_type().tag, map)
	
	@classmethod
	def from_data_item(cls, item):
		map = item.map
		return cls(map[1], map[2])
			
class CryptoECKey(RegistryItem):
	def __init__(self, data, curve=0, private_key=False):
		super().__init__()
		self.data = data
		self.curve = curve
		self.private_key = private_key
		
	@classmethod
	def registry_type(cls):
		return CRYPTO_ECKEY
	
	def to_data_item(self):
		map = {}
		if self.curve:
			map[1] = self.curve
		if self.private_key is not None:
			map[2] = self.private_key
		map[3] = self.data
		return DataItem(self.registry_type().tag, map)
	
	@classmethod
	def from_data_item(cls, item):
		map = item.map
		data = map[3]
		curve = map[1] if 1 in map else None
		private_key = map[2] if 2 in map else None
		return cls(data, curve, private_key)
	
class CryptoHDKey(RegistryItem):
	def __init__(self, props):
		super().__init__()
		if props['master']:
			self.setup_master_key(props)
		else:
			self.setup_derive_key(props)
		  
	@classmethod
	def registry_type(cls):
		return CRYPTO_HDKEY
	  
	def setup_master_key(self, props):
		self.master = True
		self.key = props['key']
		self.chain_code = props['chain_code']
		
	def setup_derive_key(self, props):
		self.master = False
		self.private_key = props['private_key']
		self.key = props['key']
		self.chain_code = props['chain_code']
		self.use_info = props['use_info']
		self.origin = props['origin']
		self.children = props['children']
		self.parent_fingerprint = props['parent_fingerprint']
		self.name = props['name']
		self.note = props['note']
		
	def bip32_key(self, include_derivation_path=False):
		parent_fingerprint = bytes(4)
		if self.master:
			version = binascii.unhexlify('0488ADE4' if not self.use_info or self.use_info.network == 0 else '04358394')
			depth = 0
			index = 0
		else:
			paths = self.origin.components
			depth = len(paths)
			last_path = paths[depth-1]
			if last_path:
				index = last_path.index + HARDENED_BIT if last_path.hardened else last_path.index
				parent_fingerprint = self.parent_fingerprint
			if self.private_key:
				version = binascii.unhexlify('0488ADE4' if not self.use_info or self.use_info.network == 0 else '04358394')
			else:
				version = binascii.unhexlify('0488B21E' if not self.use_info or self.use_info.network == 0 else '043587cf')
		depth = depth.to_bytes(1, 'big')
		index = index.to_bytes(4, 'big')
		key = encode_check(version + depth + parent_fingerprint + index + self.chain_code + self.key)
		if include_derivation_path:
			return '[%s/%s]%s' % (binascii.hexlify(self.origin.source_fingerprint).decode('utf-8'), self.origin.path(), key)
		return key
	
	def to_data_item(self):
		map = {}
		if self.master:
			map[1] = True
			map[3] = self.key
			map[4] = self.chain_code
		else:
			if self.private_key is not None:
				map[2] = self.private_key
			map[3] = self.key
			if self.chain_code:
				map[4] = self.chain_code
			if self.use_info:
				use_info = self.use_info.to_data_item()
				use_info.tag = self.use_info.registry_type().tag
				map[5] = use_info
			if self.origin:
				origin = self.origin.to_data_item()
				origin.tag = self.origin.registry_type().tag
				map[6] = origin
			if self.children:
				children = self.children.to_data_item()
				children.tag = self.children.registry_type().tag
				map[7] = children
			if self.parent_fingerprint:
				map[8] = int.from_bytes(self.parent_fingerprint, 'big')
			if self.name:
				map[9] = self.name
			if self.note:
				map[10] = self.note
		return DataItem(self.registry_type().tag, map)
	
	@classmethod
	def from_data_item(cls, item):
		map = item.map
		master = 1 in map and map[1]
		private_key = map[2]
		key = map[3]
		chain_code = map[4]
		use_info = CryptoCoinInfo.from_data_item(map[5]) if 5 in map else None
		origin = CryptoKeypath.from_data_item(map[6]) if 6 in map else None
		children = CryptoKeypath.from_data_item(map[7]) if 7 in map else None
		parent_fingerprint = bytes(4)
		if 8 in map:
			parent_fingerprint = map[8].to_bytes(4, 'big')
		name = map[9] if 9 in map else None
		note = map[10] if 10 in map else None
		return cls({
			'master': master,
			'private_key': private_key,
			'key': key,
			'chain_code': chain_code,
			'use_info': use_info,
			'origin': origin,
			'children': children,
			'parent_fingerprint': parent_fingerprint,
			'name': name,
			'note': note
		})
		
class CryptoKeypath(RegistryItem):
	def __init__(self, components, source_fingerprint, depth):
		super().__init__()
		self.components = components
		self.source_fingerprint = source_fingerprint
		self.depth = depth
		  
	@classmethod
	def registry_type(cls):
		return CRYPTO_KEYPATH
	
	def path(self):
		if not self.components:
			return None
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
		if self.source_fingerprint:
			map[2] = int.from_bytes(self.source_fingerprint, 'big')
		if self.depth:
			map[3] = self.depth
		return DataItem(self.registry_type().tag, map)
	
	@classmethod
	def from_data_item(cls, item):
		map = item.map
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
		source_fingerprint = bytes(4)
		if 2 in map:
			source_fingerprint = map[2].to_bytes(4, 'big')
		depth = map[3]
		return cls(path_components, source_fingerprint, depth)
	
class MultiKey(RegistryItem):
	def __init__(self, threshold, ec_keys, hd_keys):
		super().__init__()
		self.threshold = threshold
		self.ec_keys = ec_keys
		self.hd_keys = hd_keys
		  
	@classmethod
	def registry_type(cls):
		return None
	
	def to_data_item(self):
		map = {}
		map[1] = self.threshold
		combined_keys = self.ec_keys[:] + self.hd_keys[:]
		keys = []
		for key in combined_keys:
			item = key.to_data_item()
			item.tag = key.registry_type().tag
			keys.append(item)
		map[2] = keys
		return DataItem(None, map)        
	
	@classmethod
	def from_data_item(cls, item):
		map = item.map
		threshold = map[1]
		keys = map[2]
		ec_keys = []
		hd_keys = []
		for key in keys:
			if key.tag == CRYPTO_HDKEY.tag:
				hd_keys.append(CryptoHDKey.from_data_item(key))
			elif key.tag == CRYPTO_ECKEY.tag:
				ec_keys.append(CryptoECKey.from_data_item(key))
		return cls(threshold, ec_keys, hd_keys)
	
class CryptoOutput(RegistryItem):
	def __init__(self, script_expressions, crypto_key):
		super().__init__()
		self.script_expressions = script_expressions
		self.crypto_key = crypto_key
		  
	@classmethod
	def registry_type(cls):
		return CRYPTO_OUTPUT
	
	def descriptor(self):
		descriptor = io.StringIO()
		
		for script_expression in self.script_expressions:
			descriptor.write(script_expression.expression + '(')
		
		if isinstance(self.crypto_key, MultiKey):
			descriptor.write(str(self.crypto_key.threshold) + ',')
			descriptor.write(','.join([key.bip32_key(True) for key in self.crypto_key.hd_keys]))
				
		for _ in self.script_expressions:
			descriptor.write(')')
			
		d = descriptor.getvalue()
		descriptor.close()
  
		return d + '#' + descriptor_checksum(d)
	
	def hd_key(self):
		if isinstance(self.crypto_key, CryptoHDKey):
			return self.crypto_key
		return None
	
	def ec_key(self):
		if isinstance(self.crypto_key, CryptoECKey):
			return self.crypto_key
		return None
	
	def multi_key(self):
		if isinstance(self.crypto_key, MultiKey):
			return self.crypto_key
		return None
	
	def to_data_item(self):
		item = self.crypto_key.to_data_item()
		if self.ec_key() is not None or self.hd_key() is not None:
			item.tag = self.crypto_key.registry_type().tag
		
		cloned_se = self.script_expressions[:]
		cloned_se.reverse()
		for expression in cloned_se:
			if not item.tag:
				item.tag = expression.tag
			else:
				item = DataItem(expression.tag, item)
		return item        
	
	@classmethod
	def from_data_item(cls, item):
		script_expressions = []
		tmp_item = item
		while True:
			tag = tmp_item.tag
			if tag in script_expressions_by_tag:
				se = script_expressions_by_tag[tag]
				script_expressions.append(se)
				if isinstance(tmp_item.map, DataItem):
					tmp_item = tmp_item.map
				else:
					break
			else:
				break
		se_length = len(script_expressions)
		is_multi_key = se_length > 0 and (script_expressions[se_length-1].expression == MULTISIG.expression or script_expressions[se_length-1].expression == SORTED_MULTISIG.expression)
		if is_multi_key:
			return cls(script_expressions, MultiKey.from_data_item(tmp_item))
		
		if tmp_item.tag == CRYPTO_HDKEY.tag:
			return cls(script_expressions, CryptoHDKey.from_data_item(tmp_item))
		else:
			return cls(script_expressions, CryptoECKey.from_data_item(tmp_item))
		
class CryptoPSBT(Bytes):
	@classmethod
	def registry_type(cls):
		return CRYPTO_PSBT
	
class CryptoBIP39(RegistryItem):
	def __init__(self, words, lang):
		super().__init__()
		self.words = words
		self.lang = lang
  
	@classmethod
	def registry_type(cls):
		return CRYPTO_BIP39
	
	def to_data_item(self):
		map = {
			1: self.words,
			2: self.lang
		}
		return DataItem(self.registry_type().tag, map)
	
	@classmethod
	def from_data_item(cls, item):
		map = item.map
		words = map[1]
		lang = map[2] if 2 in map else 'en'
		return cls(words, lang)
	
