from distutils.core import setup

#scripts=['heaphopper_client.py'],
try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='heaphopper',
    version='1.0',
    description='The HeapHopper',
    url='https://github/angr/heaphopper',
    packages=packages,
    install_requires=[
        'ana',
        'angr',
        'IPython',
        'psutil',
        'pyyaml',
        'pyelftools',
   ],
)
