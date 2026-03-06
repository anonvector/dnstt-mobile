.PHONY: build clean

build:
	gomobile bind -target android/arm,android/arm64 -androidapi 21 \
		-o ../app/libs/dnstt.aar ./mobile

clean:
	rm -f ../app/libs/dnstt.aar ../app/libs/dnstt-sources.jar
