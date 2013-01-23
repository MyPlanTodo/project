EXEC = pdd

all : 
	# pour le fichier en .dvi
	xelatex $(EXEC);
	# on compile une deuxième pour mettre à jour un éventuel sommaire
	xelatex $(EXEC);

clean : 
	rm -f *.log *.bbl *.blg *.out *.toc *.aux *~ *.dvi
