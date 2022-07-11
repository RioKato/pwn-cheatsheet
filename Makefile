
PDF= heap.pdf kernel.pdf v8.pdf
JPG= heap_trans.jpg terminate.jpg

OBJ= $(JPG) $(PDF)

%.jpg: %.gv
	dot -Tjpg $< -o $@

%.pdf: %.md
	# pandoc $< -o $@ -V geometry:margin=1in -N
	md-to-pdf --stylesheet https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/2.10.0/github-markdown.min.css --body-class markdown-body $<

all: $(OBJ)
