#include "benchmarks.hpp"
#include <chrono>
#include <iomanip>
#include <map>
#include <sstream>
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto_helpers.hpp"
#include "crypto/hash.hpp"

using std::endl;
using std::left;
using std::right;
using std::setfill;
using std::setprecision;
using std::setw;

using namespace crypto;

int min(int a, int b) { return (a < b) ? a : b; }

typedef crypto::EllipticCurveScalar Scalar;
typedef ge_p3 Point;

static uint8_t global_result = 0;
void update_global_result(const void *data, size_t size) {
	for (size_t i = 0; i != size; ++i)
		global_result ^= reinterpret_cast<const uint8_t *>(data)[i];
}

#define CLOCK(X)                                                                                                       \
	auto start = std::chrono::high_resolution_clock::now();                                                            \
	for (int i = 0; i < count; ++i) {                                                                                  \
		X;                                                                                                             \
		update_global_result(&result, sizeof(result));                                                                 \
		static_assert(std::is_trivially_copyable<decltype(result)>::value, "result must be trivially copyable");       \
	}                                                                                                                  \
	auto finish     = std::chrono::high_resolution_clock::now();                                                       \
	long time_delta = static_cast<long>(std::chrono::duration_cast<std::chrono::nanoseconds>(finish - start).count()); \
	return time_delta;

Point p2_to_p3(const ge_p2 &p) {
	Point result{};
	fe_copy(result.X, p.X);
	fe_copy(result.Y, p.Y);
	fe_copy(result.Z, p.Z);
	fe_1(result.T);
	return result;
}

long test_scalarmult_base(int count, const Scalar *scalars) {
	CLOCK(const Scalar &s = scalars[i];

	      Point result;
	      ge_scalarmult_base(&result, &s);)
}

long test_scalarmult(int count, const Scalar *scalars, const Point *points) {
	CLOCK(const Scalar &s = scalars[i]; const Point &p = points[i];

	      Point result;
	      ge_scalarmult3(&result, &s, &p);)
}

long test_scalarmult_aligned(int count, const std::pair<Scalar, Point> *merged_sp) {
	CLOCK(Scalar s; Point p; std::tie(s, p) = merged_sp[i];

	      Point result;
	      ge_scalarmult3(&result, &s, &p);)
}

long test_scalarmult_via_phantom_point(int count, const Scalar *scalars, const Point *points) {
	Scalar sc0;
	sc_0(&sc0);
	CLOCK(const Scalar &s = scalars[i]; const Point &p = points[i];

	      ge_p3 result;
	      ge_double_scalarmult_base_vartime3(&result, &sc0, &p, &s);)
}

long test_scalarmult_via_double_phantom_aligned(int count, const std::pair<Scalar, Point> *merged_sp) {
	Scalar sc0;
	sc_0(&sc0);
	CLOCK(Scalar s; Point p; std::tie(s, p) = merged_sp[i];

	      ge_p3 result;
	      ge_double_scalarmult_base_vartime3(&result, &sc0, &p, &s);)
}

long test_double_scalarmult_base(int count, const Scalar *scalars, const Point *points) {
	CLOCK(const Scalar &s = scalars[i]; const Point &p = points[i];

	      ge_p3 result;
	      ge_double_scalarmult_base_vartime3(&result, &s, &p, &s);)
}

long test_double_scalarmult_badprecomp(int count, const Scalar *scalars, const Point *points) {
	CLOCK(const Scalar &s = scalars[i]; const Point &p = points[i];

	      ge_p3 result;
	      ge_dsmp cache;
	      ge_dsm_precomp(&cache, &p);
	      ge_double_scalarmult_precomp_vartime3(&result, &s, &p, &s, &cache);)
}

long test_double_scalarmult_precomp(int count, const Scalar *scalars, const Point *points, const ge_dsmp *precomp) {
	CLOCK(const Scalar &s = scalars[i]; const Point &p = points[i]; const ge_dsmp &cache = precomp[i];

	      ge_p3 result;
	      ge_double_scalarmult_precomp_vartime3(&result, &s, &p, &s, &cache);)
}

long test_double_scalarmult(int count, const Scalar *scalars, const Point *points) {
	CLOCK(const Point &p = points[i]; const Scalar &s = scalars[i]; cryptoEllipticCurveScalar s2{};

	      sc_add(&s2, &s, &s);
	      ge_dsmp dsm_precomp;
	      ge_dsm_precomp(&dsm_precomp, &p);
	      ge_p3 result;
	      ge_double_scalarmult_precomp_vartime3(&result, &s, &p, &s2, &dsm_precomp);)
}

long test_double_scalarmult_simple(int count, const Scalar *scalars, const Point *points) {
	CLOCK(const Point &p = points[i]; const Scalar &s = scalars[i]; Scalar s2{};

	      sc_add(&s2, &s, &s);
	      auto pmul1  = crypto::ge_scalarmult3(s, p);
	      auto pmul2  = crypto::ge_scalarmult3(s2, p);
	      auto result = crypto::ge_add(pmul1, pmul2);)
}

long test_double_scalarmult_simple_opt(int count, const Scalar *scalars, const Point *points) {
	Scalar sc0;
	sc_0(&sc0);
	CLOCK(const Scalar &s = scalars[i]; const Point &p = points[i]; Scalar s2{};

	      sc_add(&s2, &s, &s);
	      auto pmul1  = crypto::ge_double_scalarmult_base_vartime3(s, p, sc0);
	      auto pmul2  = crypto::ge_double_scalarmult_base_vartime3(s2, p, sc0);
	      auto result = crypto::ge_add(pmul1, pmul2);)
}

long test_double_scalarmult_simple_aligned(int count,
    const std::tuple<Scalar, Scalar, Point, Point> *merged_double_points) {
	Scalar sc0;
	sc_0(&sc0);
	CLOCK(Scalar s1; Scalar s2; Point p1; Point p2; std::tie(s1, s2, p1, p2) = merged_double_points[i];

	      auto pmul1  = crypto::ge_double_scalarmult_base_vartime3(s1, p1, sc0);
	      auto pmul2  = crypto::ge_double_scalarmult_base_vartime3(s2, p2, sc0);
	      auto result = crypto::ge_add(pmul1, pmul2);)
}

long test_frombytes(int count, const EllipticCurvePoint *bytes) {
	CLOCK(auto &b = bytes[i];

	      auto result = ge_frombytes_vartime(b);)
}

long test_fromfe_frombytes(int count, const EllipticCurvePoint *bytes) {
	CLOCK(auto &b = bytes[i];

	      ge_p2 result;
	      ge_fromfe_frombytes_vartime(&result, b.data);)
}

long test_check_subgroup(int count, const Point *points) {
	CLOCK(auto &p    = points[i]; ge_dsmp cache; ge_dsm_precomp(&cache, &p);
	      int result = ge_check_subgroup_precomp_vartime(&cache);)
}

long test_sc_mul(int count, const Scalar *a, const Scalar *b) {
	CLOCK(EllipticCurveScalar result; sc_mul(&result, &a[i], &b[i]));
}

long test_sc_sub(int count, const Scalar *a, const Scalar *b) {
	CLOCK(EllipticCurveScalar result; sc_sub(&result, &a[i], &b[i]));
}

long test_sc_mul_sub(int count, const Scalar *a, const Scalar *b, const Scalar *c) {
	CLOCK(EllipticCurveScalar result; sc_mulsub(&result, &a[i], &b[i], &c[i]));
}

long test_sc_invert(int count, const Scalar *a) { CLOCK(EllipticCurveScalar result; sc_invert(&result, &a[i])); }

long test_precomp(int count, const Point *a) { CLOCK(ge_dsmp result; ge_dsm_precomp(&result, &a[i])); }

// Example with std::string will fail compilation
// long test_string(int count){
//	CLOCK(std::string result;)
//}

void benchmark_crypto_ops(int count, std::ostream &out) {
	std::vector<Scalar> scalars(count);
	std::vector<Point> points(count);
	std::vector<ge_dsmp> precomp(count);
	std::vector<crypto::EllipticCurvePoint> bytes(count);
	std::vector<std::pair<Scalar, Point>> merged_sp(count);
	auto merged_double_points =
	    std::make_unique<std::tuple<Scalar, Scalar, Point, Point>[]>(count);  // Also ok in C++14

	for (int i = 0; i < count; ++i) {
		KeyPair k    = random_keypair();
		bytes[i]     = k.public_key;
		auto s       = k.secret_key;
		auto p       = ge_frombytes_vartime(k.public_key);
		scalars[i]   = s;
		points[i]    = p;
		merged_sp[i] = std::make_pair(s, p);

		k                             = random_keypair();
		auto s2                       = k.secret_key;
		auto p2                       = ge_frombytes_vartime(k.public_key);
		merged_double_points.get()[i] = std::make_tuple(s, s2, p, p2);

		ge_dsm_precomp(&precomp[i], &p);
	}

	std::map<std::string, long> benchmark_results;

	benchmark_results.insert(std::make_pair("test_frombytes", test_frombytes(count, bytes.data())));
	benchmark_results.insert(std::make_pair("test_fromfe_frombytes", test_fromfe_frombytes(count, bytes.data())));
	benchmark_results.insert(std::make_pair("test_check_subgroup", test_check_subgroup(count, points.data())));
	benchmark_results.insert(std::make_pair(
	    "test_double_scalarmult_base", test_double_scalarmult_base(count, scalars.data(), points.data())));
	benchmark_results.insert(std::make_pair(
	    "test_double_scalarmult_badprecomp", test_double_scalarmult_badprecomp(count, scalars.data(), points.data())));
	benchmark_results.insert(std::make_pair("test_double_scalarmult_precomp",
	    test_double_scalarmult_precomp(count, scalars.data(), points.data(), precomp.data())));
	benchmark_results.insert(std::make_pair(
	    "test_double_scalarmult_simple", test_double_scalarmult_simple(count, scalars.data(), points.data())));
	benchmark_results.insert(std::make_pair(
	    "test_double_scalarmult_simple_opt", test_double_scalarmult_simple_opt(count, scalars.data(), points.data())));
	benchmark_results.insert(std::make_pair("test_double_scalarmult_simple_aligned",
	    test_double_scalarmult_simple_aligned(count, merged_double_points.get())));
	benchmark_results.insert(std::make_pair("test_scalarmult_base", test_scalarmult_base(count, scalars.data())));
	benchmark_results.insert(std::make_pair("test_scalarmult", test_scalarmult(count, scalars.data(), points.data())));
	benchmark_results.insert(
	    std::make_pair("test_scalarmult_aligned", test_scalarmult_aligned(count, merged_sp.data())));
	benchmark_results.insert(std::make_pair(
	    "test_scalarmult_via_phantom_point", test_scalarmult_via_phantom_point(count, scalars.data(), points.data())));
	benchmark_results.insert(std::make_pair("test_scalarmult_via_double_phantom_aligned",
	    test_scalarmult_via_double_phantom_aligned(count, merged_sp.data())));
	benchmark_results.insert(
	    std::make_pair("test_double_scalarmult", test_double_scalarmult(count, scalars.data(), points.data())));

	benchmark_results["test_precomp"]    = test_precomp(count, points.data());
	benchmark_results["test_sc_mul"]     = test_sc_mul(count, scalars.data(), scalars.data());
	benchmark_results["test_sc_sub"]     = test_sc_sub(count, scalars.data(), scalars.data());
	benchmark_results["test_sc_mul_sub"] = test_sc_mul_sub(count, scalars.data(), scalars.data(), scalars.data());
	benchmark_results["test_sc_invert"]  = test_sc_invert(count, scalars.data());

	for (auto &tup : benchmark_results) {
		auto &name       = tup.first;
		auto &time_delta = tup.second;
		std::stringstream output;
		double total_ms = time_delta / 1000000.;
		output << left << setw(6) << count << " cycles  " << right << setw(10) << std::fixed << setprecision(3)
		       << total_ms << " ms  " << right << setw(7) << std::fixed << setprecision(3) << total_ms / count
		       << " ms/op  " << left << name << endl;
		out << output.str();
	}
	out << "global_result=" << int(global_result) << endl;  // so compiler cannot optimize calcs out
}
