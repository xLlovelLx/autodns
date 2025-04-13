from setuptools import setup, find_packages

setup(
    name="dns_enum_advanced",
    version="1.0.0",
    description="Advanced DNS Enumeration Tool",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourgithubuser/advanced-dns-enum",
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
            "dns-enum=scripts.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)