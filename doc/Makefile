all: nflog-acctd.info nflog-acctd.html

nflog-acctd.dvi: nflog-acctd.texi
	texi2dvi nflog-acctd.texi

nflog-acctd.info: nflog-acctd.texi
	makeinfo nflog-acctd.texi

nflog-acctd.html:
	makeinfo --no-split --html nflog-acctd.texi

clean:
	rm -f *.dvi *.info *.xml *.html \
		*.aux *.cp *.cps *.fn *.ky *.log *.pg *.toc *.tp *.vr

