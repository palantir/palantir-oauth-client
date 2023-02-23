import subprocess
import sys
from os import path, makedirs, system

from setuptools import find_packages, setup, Command

try:
    raw_gitversion = (
        subprocess.check_output(
            "git describe --tags --always --first-parent".split()
        )
        .decode()
        .strip()
        .split("-")
    )
    gitversion = (
        raw_gitversion[0]
        if len(raw_gitversion) == 1
        else f"{raw_gitversion[0]}.dev{raw_gitversion[1]}"
    )
    open("palantir_oauth_client/_version.py", "w").write(
        '__version__ = "{}"\n'.format(gitversion)
    )
    if not path.exists("build"):
        makedirs("build")
except subprocess.CalledProcessError:
    print("outside git repo, not generating new version string")
exec(open("palantir_oauth_client/_version.py").read())


class FormatCommand(Command):
    """Enables setup.py format."""

    description = "Reformat python files using 'black'"
    user_options = [
        ("check", "c", "Don't write the files back, just return the status")
    ]

    def initialize_options(self):
        self.check = False

    def finalize_options(self):
        if self.check != False:
            self.check = True
        pass

    def run(self):
        try:
            if self.check:
                code = self.blackCheck()
            else:
                code = self.black()
            if code == 0:
                sys.exit(0)
            else:
                sys.exit(1)
        except OSError:
            pass

    @staticmethod
    def black():
        return system("black --line-length 79 *.py **/*.py")

    @staticmethod
    def blackCheck():
        return system("black --check --quiet --line-length 79 *.py **/*.py")


class CondaBuild(Command):
    """Enables setup.py condabuild."""

    user_options = []
    description = "Build conda package"

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.conda_build()

    @staticmethod
    def conda_build():
        return system(
            "conda-build --no-anaconda-upload --output-folder build/conda --python 27 conda_recipe"
        )


version = __version__
setup(
    name="palantir-oath-client",
    version=__version__,
    description="OAuth2 client for Palantir Foundry",
    author="Palantir Technologies, Inc.",
    url="https://github.com/palantir/palantir-oauth-client",
    packages=find_packages(exclude=["test*", "integration*"]),
    python_requires=">=3",
    install_requires=["oauthlib", "requests", "requests-oauthlib", "typing"],
    extras_require={
        "test": ["pytest", "mockito", "pytest-mockito", "expects", "tox"]
    },
    cmdclass={
        "format": FormatCommand,
        "condabuild": CondaBuild,
    },
)
