rm -fr _build
html=_build/html
PYTHONPATH=.. ${PYTHON:=python} -msphinx . $html
[ -d download ] && cp -r download $html || echo No download directory, skipping
rm -r $html/.doctrees $html/.buildinfo
find $html -type d -exec chmod 755 {} +
find $html -type f -exec chmod 644 {} +
