# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++17 -Wall -Wextra -g

# Include directories
INCLUDES = -I. -I./include

# Source files
SRCS = ./src/main.cpp \
       ./src/layers.cpp \
       ./src/packet.cpp \
       ./src/scanners.cpp \
       ./src/utils.cpp \
       ./src/rocket.cpp \

# Object files
OBJS = $(SRCS:.cpp=.o)

# Output binary
TARGET = nshark

# Default target to build the binary
all: $(TARGET)

# Link the object files to create the final executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

# Compile each source file into an object file
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Clean target to remove object files and the binary
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean
