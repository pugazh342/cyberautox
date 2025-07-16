from setuptools import setup, find_packages

setup(
    name="cyberautox",
    version="0.1",
    packages=find_packages(),
    package_dir={'': '.'},  # Important for finding modules
    install_requires=[
        'click',
        'requests',
        'shodan'
    ],
)