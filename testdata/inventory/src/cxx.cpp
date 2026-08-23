#include <cstdio>
namespace lading {
  struct Widget {
    int answer(int x) const { return x + 1; }
  };
  int greet(const char* name) {
    std::puts(name);
    return 0;
  }
}
int main() {
  lading::Widget w;
  return lading::greet("LADING_CXX_MARKER") + w.answer(0);
}
