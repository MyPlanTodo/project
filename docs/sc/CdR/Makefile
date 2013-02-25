OUT = SC_CdR

$(OUT).pdf: $(OUT).tex
	xelatex $< ; xelatex $<

clean:
	rm -f *.out *.nav *.log *.toc *.aux *~

cleanall: clean
	rm -f $(OUT).pdf
