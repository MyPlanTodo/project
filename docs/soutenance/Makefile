OUT = soutenance

$(OUT).pdf : $(OUT).tex
	pdflatex $<

clean: 
	rm -f *~ *.toc *.aux *.log *.out *.nav *.snm

cleanall: clean
	rm -f $(OUT).pdf
