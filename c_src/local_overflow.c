#include <sys/types.h>

void overflow(int *buffer, size_t buffer_size) {
  buffer[buffer_size] = 1;
}

int main(int argc, char **argv) {
  const size_t length = 10;
  int buffer[length];

  overflow(buffer, length);

  return 0;
}
