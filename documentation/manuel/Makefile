OUT1 = 1.installation_lecteur
OUT2 = 2.dev_applet
OUT3 = 3.installation_applet

$(OUT1).pdf: $(OUT1).tex 
	pdflatex $< ; pdflatex $<

$(OUT2).pdf: $(OUT2).tex 
	pdflatex $< ; pdflatex $<

$(OUT3).pdf: $(OUT3).tex 
	pdflatex $< ; pdflatex $<

clean:
	rm -f *.out *.nav *.log *.toc *.aux *~

cleanall: clean
	rm -f $(OUT1).pdf $(OUT2).pdf $(OUT3).pdf
