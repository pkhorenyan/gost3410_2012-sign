version = open("../VERSION", "rb").read().strip().decode("ascii")

extensions = ["sphinx.ext.autodoc"]
templates_path = ["_templates"]
source_suffix = ".rst"
master_doc = "index"
project = "pyderasn"
copyright = "2017-2022, Sergey Matveev"
author = "Sergey Matveev"
version = version
release = version
language = None
exclude_patterns = ["_build"]
pygments_style = "sphinx"
todo_include_todos = False
html_theme = "classic"
html_static_path = ["_static"]
html_sidebars = {}
