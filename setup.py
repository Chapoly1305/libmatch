from setuptools import setup, find_packages

setup(
    name='bdsig',
    description='Library matcher for binaries given a database of library object files.',
    version='0.0.1.1',
    packages=find_packages(),
    python_requires='>=3.10,<3.12',  # autoblob uses 'imp' module removed in Python 3.12
    install_requires=[
        'angr>=9.2.192',
        'networkx>=3.0',
        'PyYAML>=6.0',
        'makeelf>=0.3.0',
        'clint>=0.5.1'
    ],
    author='Eric Gustafson',
    author_email='subwire@gmail.com',
    license='BSD-2-Clause',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Disassemblers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)
