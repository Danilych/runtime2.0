
from weakref import ref
from collections import MutableMapping

from utils.generators import generate_unique_name
from utils.properties import lazy, weak, roproperty

from ..generic import MemoryBase
from .library import MemoryLibrarySketch


NAME_BASE = "library"


def wrap_rename(instance):
    instance = ref(instance)

    def on_rename(item, name):
        self = instance()
        with self._owner.lock:
            del self._items[item.name]
            if name in self._items:
                name = generate_unique_name(name, self._items)
            self._items[name] = item
            return name

    return on_rename


def wrap_complete(instance):
    instance = ref(instance)

    def on_complete(item):
        self = instance()
        with self._owner.lock:
            if item._name is None or item._name in self._items:
                item._name = generate_unique_name(item._name or NAME_BASE, self._items)
            self._items[item._name] = item
            return wrap_rename(self)

    return on_complete


@weak("_owner")
class MemoryLibraries(MemoryBase, MutableMapping):

    @lazy
    def _items(self):
        return {}

    def __init__(self, owner):
        self._owner = owner

    owner = roproperty("_owner")

    def new_sketch(self):
        return MemoryLibrarySketch(wrap_complete(self), self._owner)

    def new(self, name=None):
        item = self.new_sketch()
        item.name = name
        return ~item

    # unsafe
    def compose(self, ident=u"", file=None, shorter=False):
        libraries = tuple(library for library in self._items.itervalues())
        if libraries:
            file.write(u"%s<Libraries>\n" % ident)
            for library in libraries:
                library.compose(ident=ident + u"\t", file=file, shorter=shorter)
            file.write(u"%s</Libraries>\n" % ident)

    def clear(self):
        if "_items" in self.__dict__:
            with self._owner.lock:
                del self._items

    def __getitem__(self, key):
        return self._items[key]

    def __setitem__(self, key, value):
        raise Exception(u"Use 'new' to create new library")

    def __delitem__(self, key):
        with self._owner.lock:
            item = self._items[key]
            del self._items[item.name]

    def __iter__(self):
        return iter(self.__dict__.get("_items", ()))

    def __len__(self):
        return len(self.__dict__.get("_items", ()))

    def __str__(self):
        return "libraries of %s" % self._owner
