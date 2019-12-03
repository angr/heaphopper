class AbstractHeapPlugin():
    def __init__(self, binary_name, config):
        self.binary_name = binary_name
        self.config = config
        self.proj = None
        self.state = None
        self.finds = None
        self.avoids = None
        # Target for symbolic allocations
        self.alloc_target_var = None
        # Target for symbolic writes
        self.write_target_var = None

    @classmethod
    def name(cls):
        return "Abstract"

    def setup_state(self):
        pass

    def setup_project(self):
        pass

    def process_state(self, num_results, state, write_state, fd): # pylint: disable=unused-argument
        pass

    def hook(self):
        pass

    def post_corruption_analysis(self, state): # pylint: disable=no-self-use
        return state



from .glibc import GlibcPlugin
from .post_corruption import PostCorruptionPlugin
