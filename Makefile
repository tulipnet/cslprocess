.PHONY: cslprocess install doc clean

cslprocess:
	dune build
	rm -f ./cslprocess
	ln -s _build/default/bin/cslprocess.exe ./cslprocess

install: cslprocess
	sudo dune install --prefix=/usr/local --verbose

doc: cslprocess
	dune build @doc
	rm -f _build/default/_doc/_html/odoc.support/odoc.css
	cp odoc.css _build/default/_doc/_html/odoc.support/
	rm -f ./doc.html
	ln -s _build/default/_doc/_html/index.html ./doc.html

clean:
	dune clean
	rm -f cslprocess doc.html
