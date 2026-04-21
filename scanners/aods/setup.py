#!/usr/bin/env python3
"""
AODS (Automated OWASP Dynamic Scan) Framework Setup
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="aods-framework",
    version="4.2.0",
    author="AODS Development Team",
    author_email="contact@isi-ttusds.com",
    description="Android Security Analysis Framework with AI/ML capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/OnDefend/AODS",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", 
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0", 
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "coverage>=6.0.0",
            "pre-commit>=3.0.0"
        ],
        "analysis": [
            "frida>=16.0.0",
            "mitmproxy>=9.0.0",
            "objection>=1.11.0"
        ],
        "ml": [
            "scikit-learn>=1.3.0",
            "xgboost>=2.0.0",
            "tensorflow>=2.13.0",
            "torch>=2.0.0",
            "transformers>=4.30.0",
            "sentence-transformers>=2.2.0",
            "numpy>=1.24.0",
            "pandas>=2.0.0"
        ],
        "ai": [
            "shap>=0.43.0",
            "lime>=0.2.0",
            "scikit-learn>=1.3.0",
            "xgboost>=2.0.0"
        ],
        "docs": [
            "mkdocs>=1.5.0",
            "mkdocs-material>=9.0.0"
        ],
        "enterprise": [
            "prometheus-client>=0.17.0",
            "redis>=4.5.0",
            "celery>=5.3.0"
        ],
        "all": [
            "frida>=16.0.0",
            "scikit-learn>=1.3.0",
            "xgboost>=2.0.0",
            "shap>=0.43.0",
            "transformers>=4.30.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "aods=dyna:main",
            "dyna=dyna:main",
            "aods-batch=core.enterprise.batch_cli:main",
            "aods-enterprise=core.enterprise.batch_cli:enterprise_main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
