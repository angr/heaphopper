class AbstractHeapHook():
    def __init__(self, binary_name, config):
        self.binary_name = binary_name
        self.config = config
        self.proj = None
        self.state = None
        self.finds = None
        self.avoids = None

    @classmethod
    def name(self):
        return "Abstract"

    def hook(self, binary_name, config):
        return None



from .glibc import GlibcHook