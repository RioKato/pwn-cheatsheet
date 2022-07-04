
PDF= heap.pdf kernel.pdf v8.pdf
JPG= heap_trans.jpg terminate.jpg

OBJ= $(JPG) $(PDF)

%.jpg: %.gv
	dot -Tjpg $< -o $@

%.pdf: %.md
	# pandoc $< -o $@ -V geometry:margin=1in -N
	# markdown-pdf $< -o $@
	md-to-pdf $<

all: $(OBJ)
