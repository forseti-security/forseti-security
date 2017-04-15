all: forseti proxy

clean:
	python setup.py clean --all

proxy:
	sh ./proxy/build.sh

forseti:
	python setup.py build

install:
	python setup.py install
