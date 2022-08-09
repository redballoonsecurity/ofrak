VPATH = ../assets

.PHONY: all
all: ../assets/animation.png

../assets/animation.png: t1.png t2.png t3.png t4.png t5.png
	ffmpeg -y -r 0.7 -pattern_type glob -i "../assets/t*.png" -plays 0 -f apng ../assets/animation.png
