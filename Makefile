####### Compiler, tools and options

CXXFLAGS      = -O2 -march=x86-64 -mtune=generic -std=gnu++1y
TARGET = cdns

####### Compile

$(TARGET): main.cpp 
	g++ -c $(CXXFLAGS) -o $(TARGET) main.cpp

####### Install

install: $(TARGET)
	install -m 755 -o root $(TARGET) /usr/local/bin/$(TARGET)
