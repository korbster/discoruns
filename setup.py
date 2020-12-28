from setuptools import setup

setup(
    name='discoruns',
    version='0.1.0',
    url='https://github.com/korbster/discoruns',
    author='Korbinian Karl',
    description='Python library for windows persistence mechanism extraction',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=['discoruns', "discoruns.artifacts", "discoruns.mechanisms", "discoruns.wrapper"],
    install_requires=[
        'forensicstore>=0.17.0,<0.18.0',
        'tabulate==0.8.7',
    ],
    include_package_data=True,
    entry_points={
        'console_scripts':
            ['discoruns = discoruns.main:main']
    },
    zip_safe=False,
)
