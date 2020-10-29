from distutils.core import setup

setup(
    name='embit',
    version='0.1.0',
    packages=['embit',],
    license='MIT license',
    url='https://github.com/diybitcoinhardware/embit',
    description = 'yet another bitcoin library',
    long_description="A minimal bitcoin library for MicroPython and Python3 with a focus on embedded systems.",
    author = 'Stepan Snigirev',
    author_email = 'snigirev.stepan@gmail.com',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: Flask",
    ],
)
