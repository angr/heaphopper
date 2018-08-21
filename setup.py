from distutils.core import setup

setup(
    name='heaphopper',
    version='1.0',
    description='The HeapHopper',
    packages=['heaphopper'],
    scripts=['heaphopper.py'],
    install_requires=[
        'ana',
        'angr',
        'claripy',
        'cle',
        'IPython',
        'psutil',
        'pyyaml',
        'pyelftools',
   ],
)
