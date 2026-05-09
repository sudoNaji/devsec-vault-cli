from setuptools import find_packages, setup

setup(
    name="devsec-vault",
    version="2.0.0",
    description="Layered secret detection CLI — files, staged, git history",
    package_dir={"": "src"},
    py_modules=["cli", "scanner", "patterns", "report", "baseline"],
    install_requires=["click>=8.1.0", "rich>=13.0.0"],
    entry_points={
        "console_scripts": [
            "devsec-vault=cli:cli",
        ],
    },
    python_requires=">=3.10",
)
