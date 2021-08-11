from urtypes import RegistryType, Bytes

CRYPTO_PSBT = RegistryType('crypto-psbt', 310)

class PSBT(Bytes):
	@classmethod
	def registry_type(cls):
		return CRYPTO_PSBT