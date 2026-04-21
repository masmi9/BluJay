from setuptools import setup, find_packages

setup(
    name="iods",
    version="1.0.0",
    description="iOS OWASP Dynamic Scan Framework – iOS IPA Security Testing Platform",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "pydantic>=2.0.0",
        "rich>=13.0.0",
        "structlog>=23.0.0",
        "pyyaml>=6.0.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "iods=ios_scan:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
    ],
)
