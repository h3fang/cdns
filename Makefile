####### Compiler, tools and options

CXXFLAGS = -pipe -O2 -march=native -mtune=native
TARGET = cdns

####### Compile

$(TARGET): main.cpp 
	g++ $(CXXFLAGS) -o $(TARGET) -lpthread main.cpp

####### Install

install: $(TARGET)
	install -m 755 -o root $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -f $(TARGET) *.o
