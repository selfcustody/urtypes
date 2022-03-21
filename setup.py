from setuptools import setup, find_namespace_packages

setup(
    name="urtypes",
    version="0.1.0",
    license="MIT license",
    url="https://github.com/selfcustody/urtypes",
    description="Python implementation of the Blockchain Commons UR Types",
    author="Jeff S",
    author_email="jeffreesun@protonmail.com",
    packages=find_namespace_packages("src", include=["*"]),
    package_dir={"": "src"},
    test_suite="tests",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
