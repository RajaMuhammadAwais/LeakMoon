#!/usr/bin/env python3
"""
LeakMon Setup Script
Installs LeakMon as a command-line tool
"""

from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="leakmon",
    version="1.0.3",
    author="LeakMon Team",
    author_email="muhammadawaisturk1@gmail.com",
    description="Real-Time Secret & PII Leak Detection for Local Development",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/leakmon/leakmon",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "leakmon=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "web": ["templates/*", "static/css/*", "static/js/*"],
    },
    keywords="security secrets detection pii leak monitoring development",
    project_urls={
        "Bug Reports": "https://github.com/leakmon/leakmon/issues",
        "Source": "https://github.com/leakmon/leakmon",
        "Documentation": "https://github.com/leakmon/leakmon/wiki",
    },
)

