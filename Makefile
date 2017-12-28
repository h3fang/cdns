####### Compiler, tools and options

CXX = g++
CXXFLAGS = -pipe -O2 -march=native -mtune=native
CPPFLAGS = -MMD -MP
LDFLAGS = -lpthread -lcurl
TARGET = cdns

####### Compile

SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

-include $(SRCS:.cpp=.d)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

####### Install and clean

.PHONY: install
install: $(TARGET)
	install -m 755 -o root $(TARGET) /usr/local/bin/$(TARGET)

.PHONY: clean
clean:
	rm -f $(TARGET) *.o *.d
