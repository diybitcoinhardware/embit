from setuptools import setup, find_namespace_packages

setup(
    name="embit",
    version="0.4.5",
    license="MIT license",
    url="https://github.com/diybitcoinhardware/embit",
    description="yet another bitcoin library",
    long_description="A minimal bitcoin library for MicroPython and Python3 with a focus on embedded systems.",
    author="Stepan Snigirev",
    author_email="snigirev.stepan@gmail.com",
    packages=find_namespace_packages("src", include=["*"]),
    package_dir={"": "src"},
    package_data={"embit": ["util/prebuilt/*"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
