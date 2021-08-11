# coding: utf-8

class Tagging(object):
	__slots__ = ("tag", "obj")
	def __init__(self, tag, obj):
		self.tag = tag
		self.obj = obj
	def __eq__(self, other):
		return isinstance(other, Tagging) and self.tag == other.tag and self.obj == other.obj

class Mapping(object):
	__slots__ = ('map')
	def __init__(self, map):
		self.map = map
	def mapping(obj):
		return Mapping(obj)

class DataItem(Tagging):
	def __init__(self, tag, map):
		super().__init__(tag, Mapping(map))
		self.tag = tag
		self.map = map
  
class _Undefined(object):
	_instance = None

	def __new__(cls, *args, **kwargs):
		if not isinstance(cls._instance, cls):
			cls._instance = object.__new__(cls, *args, **kwargs)
		return cls._instance

	def __str__(self):
		return "Undefined"

	def __repr__(self):
		return "Undefined"

Undefined = _Undefined()

__all__ = ["Tagging", "Mapping", "DataItem"]