OUT = soutenance

$(OUT).pdf : $(OUT).tex
	pdflatex $<

clean: 
	rm -f *~ *.toc *.aux *.log

cleanall: clean
	rm -f $(OUT).pdf
