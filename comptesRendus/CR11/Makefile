OUT = CR11_200213

$(OUT).pdf: $(OUT).tex
	pdflatex $< ; pdflatex $<

clean:
	rm -f *.out *.nav *.log *.toc *.aux *~

cleanall: clean
	rm -f $(OUT).pdf
