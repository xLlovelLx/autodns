from setuptools import setup, find_packages

setup(
    name="autodns",
    version="1.0.0",
    description="Advanced DNS Enumeration Tool",
    author="LlovelL",
    author_email="llovellrue@gmail.com",
    url="https://github.com/xxLlovelLxx/autodns",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "dnspython>=2.6.1",
        "requests>=2.25.1",
        "lxml>=4.6.3",
        "asyncio>=3.4.3",
    ],
    entry_points={
        "console_scripts": [
            "autodns=cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)