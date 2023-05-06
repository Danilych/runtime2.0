class SingletonTwo(object):
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(SingletonTwo, cls).__new__(cls)
        return cls.instance