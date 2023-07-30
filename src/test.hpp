// SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
// SPDX-License-Identifier: MIT

#pragma once

#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace brinjin {

namespace detail {

template <typename T>
void strCatInternal(std::ostringstream& str, T&& u) {
  str << u;
}

template <typename U, typename... T>
void strCatInternal(std::ostringstream& str, U&& u, T&&... t) {
  str << u;
  strCatInternal(str, std::forward<T>(t)...);
}

}  // namespace detail

template <typename U, typename... T>
std::string strCat(U&& u, T&&... t) {
  std::ostringstream str;
  str << u;
  detail::strCatInternal(str, std::forward<T>(t)...);
  return str.str();
}

struct ScopeExit {
  ScopeExit(std::function<void()> f) : f_(std::move(f)) {}

  ~ScopeExit() { f_(); }

  std::function<void()> f_;
};

#define JOIN2_IMPL(x, y) x##y
#define JOIN2(x, y) JOIN2_IMPL(x, y)
#define SCOPE_EXIT(x) ::brinjin::ScopeExit JOIN2(_scope_exit_, __LINE__)(x);

struct BrinjinAbortTest {
  BrinjinAbortTest(std::string msg) : message(std::move(msg)) {}

  std::string message;
};

inline std::string timeSinceStr(std::chrono::steady_clock::time_point start,
                                std::chrono::steady_clock::time_point end) {
  const auto duration = end - start;
  return strCat(
      std::chrono::duration_cast<std::chrono::microseconds>(duration).count() *
          0.000001,
      "s");
}

inline std::string timeSinceStr(std::chrono::steady_clock::time_point start) {
  return timeSinceStr(start, std::chrono::steady_clock::now());
}

struct BenchmarkResult {
  uint64_t iterations = 0;
  std::chrono::nanoseconds elapsed;
};

class TestRegistry {
 public:
  static TestRegistry& get() {
    static TestRegistry registry;
    return registry;
  }

  void add(std::string name, std::function<void()>&& test) {
    if (tests_.count(name)) {
      throw std::runtime_error(strCat("Duplicate test: ", name));
    }
    tests_.emplace(std::move(name), std::move(test));
  }

  int run(int argc, char* argv[]) {
    std::set<std::string> testsToRun;
    for (int i = 1; i < argc; ++i) {
      testsToRun.insert(argv[i]);
    }
    uint32_t failures = 0;
    const auto start = std::chrono::steady_clock::now();
    for (auto& test : tests_) {
      if (!testsToRun.empty() && !testsToRun.count(test.first)) {
        continue;
      }
      const auto testStart = std::chrono::steady_clock::now();
      std::vector<std::string> errors;
      try {
        test.second();
      } catch (std::exception& e) {
        errors.emplace_back(e.what());
      } catch (BrinjinAbortTest& e) {
        errors.emplace_back(std::move(e.message));
      } catch (...) {
        errors.emplace_back("Unknown exception thrown");
      }
      if (!errors.empty()) {
        failures += 1;
        for (const auto& error : errors) {
          std::cerr << "Test '" << test.first << "': " << error << std::endl;
        }
        std::cerr << "Test '" << test.first << "' failed with " << errors.size()
                  << " errors in " << timeSinceStr(testStart) << std::endl;
      } else {
        std::cout << "Test '" << test.first << "' succeeded in "
                  << timeSinceStr(testStart) << std::endl;
      }
    }
    if (!benchmarkResults_.empty()) {
      std::cout << "\nbenchmark                                       iters   "
                   "elapsed ns    average s   average ns      iters/s"
                << "\n---------------------------------------------------------"
                   "------------------------------------------------";
      for (const auto& result : benchmarkResults_) {
        std::cout << "\n" << result.first;
        const auto itersStr = std::to_string(result.second.iterations);
        std::cout << ' ';
        for (auto i = result.first.size() + itersStr.size(); i < 52; ++i) {
          std::cout << ' ';
        }
        std::cout << itersStr;
        const auto nanosStr = std::to_string(result.second.elapsed.count());
        std::cout << ' ';
        for (auto i = nanosStr.size(); i < 12; ++i) {
          std::cout << ' ';
        }
        std::cout << nanosStr;
        const auto avgStr =
            std::to_string((result.second.elapsed.count() * 0.000000001) /
                           result.second.iterations);
        std::cout << ' ';
        for (auto i = avgStr.size(); i < 12; ++i) {
          std::cout << ' ';
        }
        std::cout << avgStr;
        const auto avgNsStr = std::to_string(static_cast<uint64_t>(
            static_cast<double>(result.second.elapsed.count()) /
            result.second.iterations));
        std::cout << ' ';
        for (auto i = avgNsStr.size(); i < 12; ++i) {
          std::cout << ' ';
        }
        std::cout << avgNsStr;
        const auto perSecStr = std::to_string(static_cast<uint64_t>(
            result.second.iterations /
            (result.second.elapsed.count() * 0.000000001)));
        std::cout << ' ';
        for (auto i = perSecStr.size(); i < 12; ++i) {
          std::cout << ' ';
        }
        std::cout << perSecStr;
      }
      std::cout << std::endl;
    }
    std::cout << "Tests completed in  " << timeSinceStr(start) << ". "
              << failures << "/" << tests_.size() << " failed. " << assertions_
              << " assertions made." << std::endl;
    return failures ? 1 : 0;
  }

  void incAssertions() { assertions_ += 1; }

  void addBenchmarkResult(std::string name, BenchmarkResult result) {
    if (!benchmarkResults_.emplace(name, result).second) {
      throw BrinjinAbortTest(strCat("Duplicate benchmark name: ", name));
    }
  }

 private:
  std::map<std::string, std::function<void()>> tests_;
  uint64_t assertions_ = 0;
  std::map<std::string, BenchmarkResult> benchmarkResults_;
};

struct TestRegistar {
  TestRegistar(std::string name, std::function<void()>&& func) {
    TestRegistry::get().add(std::move(name), std::move(func));
  }
};

class Benchmark {
 public:
  Benchmark(std::string name)
      : name_(name), start_(std::chrono::steady_clock::now()) {}

  ~Benchmark() {
    BenchmarkResult result = {
        iterations_,
        std::chrono::steady_clock::now() - start_,
    };
    TestRegistry::get().addBenchmarkResult(name_, result);
  }

  std::chrono::nanoseconds duration() const {
    return std::chrono::steady_clock::now() - start_;
  }

  void countIteration(uint64_t n) { iterations_ += n; }

 private:
  std::string name_;
  std::chrono::steady_clock::time_point start_;
  uint64_t iterations_ = 0;
};

}  // namespace brinjin

#define TEST_CASE(TestName)                                         \
  static void TestName();                                           \
  ::brinjin::TestRegistar TestName##Registrar(#TestName, TestName); \
  static void TestName()

#define BENCHMARK(name, time)                                     \
  for (::brinjin::Benchmark bench(name); bench.duration() < time; \
       bench.countIteration(1))

#define BENCHMARK_N(name, time, N)                                \
  for (::brinjin::Benchmark bench(name); bench.duration() < time; \
       bench.countIteration((N)))

#define REQUIRE(...)                                                       \
  do {                                                                     \
    ::brinjin::TestRegistry::get().incAssertions();                        \
    if (!(__VA_ARGS__)) {                                                  \
      auto msg = ::brinjin::strCat("REQUIRE(", #__VA_ARGS__, ") failed."); \
      std::cerr << __FILE__ << ":" << __LINE__ << ": FAILED: REQUIRE("     \
                << #__VA_ARGS__ << ")" << std::endl;                       \
      throw ::brinjin::BrinjinAbortTest(std::move(msg));                   \
    }                                                                      \
  } while (0)

#ifdef BRINJIN_TEST_MAIN

extern "C" int main(int argc, char* argv[]) {
  try {
    return ::brinjin::TestRegistry::get().run(argc, argv);
  } catch (...) {
    return 1;
  }
}

#endif