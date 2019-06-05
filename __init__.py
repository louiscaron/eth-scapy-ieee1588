# for pre python 3.3 compatibility:
# Prior to Python 3.3, filesystem directories, and directories within zipfiles,
# had to contain an __init__.py in order to be recognised as Python package 
# directories. Even if there is no initialisation code to run when the package
# is imported, an empty __init__.py file is still needed for the interpreter to
# find any modules or subpackages in that directory.

# This has changed in Python 3.3: now any directory on sys.path with a name
# that matches the package name being looked for will be recognised as
# contributing modules and subpackages to that package.