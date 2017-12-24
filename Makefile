####### Compiler, tools and options

CXXFLAGS      = -O2 -march=x86-64 -mtune=generic -std=gnu++1y
TARGET = cdns

####### Compile

$(TARGET): main.cpp 
	g++ $(CXXFLAGS) -o $(TARGET) -lpthread main.cpp

####### Install

install: $(TARGET)
	install -m 755 -o root $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -f $(TARGET) *.o
