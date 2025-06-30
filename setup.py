# find_packages() - Automatically includes core/, blucli/, and languages/ etc.
# entry_points - Makes blujay CLI available globally
# extras_require - Dev-only tools via pip install .[dev]
# long_description - Pulls from README.md
# zip_safe=False - Ensures the tool runs from disk, not zipped package


from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="blujay",
    version="0.1.0",
    author="Malik Smith",
    author_email="youremail@example.com",
    description="BluJay - Static Analysis Tool for Java and Python with OWASP Top Ten coverage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/blujay",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/blujay/issues",
        "Documentation": "https://github.com/yourusername/blujay/wiki"
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Developers",
        "Development Status :: 3 - Alpha"
    ],
    packages=find_packages(exclude=["tests", "examples"]),
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "asttokens>=2.4.0",
        "typed-ast>=1.5.5",
        "python-docx>=1.0.0",
        "tabulate>=0.9.0",
        "jsonschema>=4.18.0"
    ],
    extras_require={
        "dev": ["pytest", "coverage", "mypy", "black"]
    },
    entry_points={
        "console_scripts": [
            "blujay=blucli.main:main"
        ]
    },
    include_package_data=True,
    zip_safe=False,
)
