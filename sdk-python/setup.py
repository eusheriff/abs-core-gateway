from setuptools import setup, find_packages

setup(
    name="abs-core",
    version="10.2.0",
    description="Official Python SDK for ABS Core — AI Agent Governance Infrastructure",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="OCONNECTOR Technology",
    author_email="dev@oconnector.tech",
    url="https://abscore.app",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "PyJWT>=2.8.0"
    ],
    extras_require={
        "crewai": ["crewai>=0.22.0"],
        "langchain": ["langchain>=0.1.0", "langchain-core>=0.1.0"],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ]
)
