class AbstractHeapPlugin():
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

    def setup_state(self):
        pass

    def setup_project(self):
        pass

    def process_state(self):
        pass

    def hook(self):
        pass

    def post_corruption_analysis(self):
        return



from .glibc import GlibcPlugin
from .post_corruption import PostCorruptionPlugin