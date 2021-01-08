#include "benchmarks.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <functional>
#include <iomanip>
#include <map>
#include <sstream>
#include "Core/Wallet.hpp"
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto_helpers.hpp"

using std::endl;
using std::left;
using std::right;
using std::setfill;
using std::setprecision;
using std::setw;

using namespace crypto;

int min(int a, int b) { return (a < b) ? a : b; }

typedef crypto::SecretKey Scalar;
typedef ge_p3 Point;

static uint8_t global_result = 0;

void update_global_result(const void *data, size_t size) {
	for (size_t i = 0; i != size; ++i)
		global_result ^= reinterpret_cast<const uint8_t *>(data)[i];
}

struct BenchmarkResult {
	size_t count       = 0;
	long time_microsec = 0;
};

template<typename T, typename S>
BenchmarkResult benchmark(size_t count, T (*bench_fun)(S), std::vector<S> values) {
	auto start = std::chrono::high_resolution_clock::now();
	for (size_t i = 0, v = 0; i != count; ++i, ++v) {
		if (v == values.size())
			v = 0;
		auto result = bench_fun(values[v]);
		update_global_result(&result, sizeof(result));
		//		static_assert(std::is_trivially_copyable<decltype(result)>::value, "result must be trivially copyable");
	}
	auto finish     = std::chrono::high_resolution_clock::now();
	long time_delta = static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(finish - start).count());
	return BenchmarkResult{count, time_delta};
}

Point p2_to_p3(const ge_p2 &p) {
	Point result{};
	fe_copy(result.X, p.X);
	fe_copy(result.Y, p.Y);
	fe_copy(result.Z, p.Z);
	fe_1(result.T);
	return result;
}

Point test_scalarmult_base(const Scalar scalar) {
	Point result;
	ge_scalarmult_base(&result, &scalar);
	return result;
}

Point test_scalarmult(std::pair<Scalar, Point> values) {
	Point result;
	ge_scalarmult3(&result, &values.first, &values.second);
	return result;
}

ge_p3 test_scalarmult_via_phantom_point(std::pair<Scalar, Point> values) {
	Scalar sc0;
	sc_0(&sc0);
	ge_p3 result;
	ge_double_scalarmult_base_vartime3(&result, &sc0, &values.second, &values.first);
	return result;
}

ge_p3 test_double_scalarmult_base(std::pair<Scalar, Point> values) {
	ge_p3 result;
	ge_double_scalarmult_base_vartime3(&result, &values.first, &values.second, &values.first);
	return result;
}

ge_p3 test_double_scalarmult_badprecomp(std::pair<Scalar, Point> values) {
	ge_p3 result;
	ge_dsmp cache;
	ge_dsm_precomp(&cache, &values.second);
	ge_double_scalarmult_precomp_vartime3(&result, &values.first, &values.second, &values.first, &cache);
	return result;
}

ge_p3 test_double_scalarmult(std::pair<Scalar, Point> values) {
	const Point &p  = values.second;
	const Scalar &s = values.first;
	cryptoEllipticCurveScalar s2{};

	sc_add(&s2, &s, &s);
	ge_dsmp dsm_precomp;
	ge_dsm_precomp(&dsm_precomp, &p);
	ge_p3 result;
	ge_double_scalarmult_precomp_vartime3(&result, &s, &p, &s2, &dsm_precomp);
	return result;
}

ge_p3 test_double_scalarmult_simple(std::pair<Scalar, Point> values) {
	const Point &p  = values.second;
	const Scalar &s = values.first;
	Scalar s2{};

	sc_add(&s2, &s, &s);
	ge_p3 pmul1;
	ge_scalarmult3(&pmul1, &s, &p);
	ge_p3 pmul2;
	ge_scalarmult3(&pmul2, &s2, &p);
	ge_p3 result = (crypto::P3(pmul1) + crypto::P3(pmul2)).p3;
	return result;
}

ge_p3 test_double_scalarmult_simple_opt(std::pair<Scalar, Point> values) {
	Scalar sc0;
	sc_0(&sc0);
	const Scalar &s = values.first;
	const Point &p  = values.second;
	Scalar s2{};

	sc_add(&s2, &s, &s);
	ge_p3 pmul1;
	ge_double_scalarmult_base_vartime3(&pmul1, &s, &p, &sc0);
	ge_p3 pmul2;
	ge_double_scalarmult_base_vartime3(&pmul2, &s2, &p, &sc0);
	ge_p3 result = (crypto::P3(pmul1) + crypto::P3(pmul2)).p3;
	return result;
}

ge_p3 test_double_scalarmult_simple_aligned(std::tuple<Scalar, Scalar, Point, Point> merged_double_points) {
	Scalar sc0;
	sc_0(&sc0);
	Scalar s1;
	Scalar s2;
	Point p1;
	Point p2;
	std::tie(s1, s2, p1, p2) = merged_double_points;

	ge_p3 pmul1;
	ge_double_scalarmult_base_vartime3(&pmul1, &s1, &p1, &sc0);
	ge_p3 pmul2;
	ge_double_scalarmult_base_vartime3(&pmul2, &s2, &p2, &sc0);
	ge_p3 result = (crypto::P3(pmul1) + crypto::P3(pmul2)).p3;
	return result;
}

ge_p3 test_frombytes(const EllipticCurvePoint bytes) { return crypto::P3(bytes).p3; }

ge_p2 test_fromfe_frombytes(const EllipticCurvePoint bytes) {
	ge_p2 result;
	ge_fromfe_frombytes_vartime(&result, bytes.data);
	return result;
}

int test_check_subgroup(const Point point) {
	ge_dsmp cache;
	ge_dsm_precomp(&cache, &point);
	return ge_check_subgroup_precomp_vartime(&cache);
}

Scalar test_sc_mul(std::pair<Scalar, Scalar> values) {
	Scalar result;
	sc_mul(&result, &values.first, &values.second);
	return result;
}

Scalar test_sc_sub(std::pair<Scalar, Scalar> values) {
	Scalar result;
	sc_sub(&result, &values.first, &values.second);
	return result;
}

Scalar test_sc_mul_sub(std::tuple<Scalar, Scalar, Scalar> values) {
	Scalar result;
	Scalar a, b, c;
	std::tie(a, b, c) = values;
	sc_mulsub(&result, &a, &b, &c);
	return result;
}

EllipticCurveScalar test_sc_invert(const Scalar a) {
	EllipticCurveScalar result;
	sc_invert(&result, &a);
	return result;
}

Signature test_generate_signature(std::pair<PublicKey, SecretKey> values) {
	Hash h{};
	return crypto::generate_signature(h, values.first, values.second);
}

Scalar test_derive_output_secret_key(std::pair<KeyDerivation, SecretKey> values) {
	return crypto::derive_output_secret_key(values.first, 0, values.second);
}

KeyDerivation test_generate_key_derivation(std::pair<Scalar, PublicKey> values) {
	return crypto::generate_key_derivation(values.second, values.first);
}

PublicKey test_generate_output(std::pair<PublicKey, PublicKey> values) {
	cn::Hash input_hash{};
	cn::Hash view_seed{};
	cn::Hash output_seed = cn::Wallet::generate_output_seed(input_hash, view_seed, 0);
	SecretKey _sec{};
	PublicKey pub{};
	uint8_t _at;
	cn::Wallet::generate_output_secrets(output_seed, &_sec, &pub, &_at);
	PublicKey enc_output_sec;
	PublicKey shared_sec;
	PublicKey result = unlinkable_derive_output_public_key(
	    pub, input_hash, 0, values.first, values.second, &enc_output_sec, &shared_sec);
	return result;
}

// Example with std::string will fail compilation
// long test_string(int count){
//	CLOCK(std::string result;)
//}

void pprint_benchmarks(std::ostream &out, const std::map<std::string, BenchmarkResult> &benchmark_results) {
	for (auto &tup : benchmark_results) {
		auto &name = tup.first;
		std::stringstream output;
		double total_ms = tup.second.time_microsec / 1000.;  // milliseconds
		double total_s  = total_ms / 1000.;                  // seconds
		output << left << setw(6) << tup.second.count << " cycles  " << right << setw(10) << std::fixed
		       << setprecision(3) << total_ms << " ms  " << right << setw(7) << std::fixed << setprecision(3)
		       << total_ms / tup.second.count << " ms/op  " << right << setw(7) << int(tup.second.count / total_s)
		       << " op/s  " << left << name << endl;
		out << output.str();
	}
	out << "internal suffix=" << int(global_result) << endl;  // so compiler cannot optimize calcs out
}

template<typename T, typename S>
std::vector<std::pair<T, S>> mk_vec(std::vector<T> itemsT, std::vector<S> itemsS) {
	auto len = std::min(itemsT.size(), itemsS.size());
	if (len != std::max(itemsT.size(), itemsS.size()))
		throw "arguments should have the same length";
	std::vector<std::pair<T, S>> result;
	result.reserve(len);
	for (size_t i = 0; i < len; ++i) {
		result.emplace_back(std::make_pair(itemsT[i], itemsS[i]));
	}
	return result;
}

template<typename T1, typename T2, typename T3>
std::vector<std::tuple<T1, T2, T3>> mk_vec(std::vector<T1> itemsT1, std::vector<T2> itemsT2, std::vector<T3> itemsT3) {
	auto len = std::min({itemsT1.size(), itemsT2.size(), itemsT3.size()});
	if (len != std::max({itemsT1.size(), itemsT2.size(), itemsT3.size()}))
		throw "arguments should have the same length";
	std::vector<std::tuple<T1, T2, T3>> result;
	result.reserve(len);
	for (size_t i = 0; i < len; ++i) {
		result.emplace_back(std::make_tuple(itemsT1[i], itemsT2[i], itemsT3[i]));
	}
	return result;
}

template<typename T1, typename T2, typename T3, typename T4>
std::vector<std::tuple<T1, T2, T3, T4>> mk_vec(
    std::vector<T1> itemsT1, std::vector<T2> itemsT2, std::vector<T3> itemsT3, std::vector<T4> itemsT4) {
	auto len = std::min({itemsT1.size(), itemsT2.size(), itemsT3.size(), itemsT4.size()});
	if (len != std::max({itemsT1.size(), itemsT2.size(), itemsT3.size(), itemsT4.size()}))
		throw "arguments should have the same length";
	std::vector<std::tuple<T1, T2, T3, T4>> result;
	result.reserve(len);
	for (size_t i = 0; i < len; ++i) {
		result.emplace_back(std::make_tuple(itemsT1[i], itemsT2[i], itemsT3[i], itemsT4[i]));
	}
	return result;
}

void benchmark_crypto_ops(size_t count, std::ostream &out) {
	std::vector<Scalar> scalars(count);
	std::vector<PublicKey> public_keys(count);
	std::vector<KeyDerivation> derivations(count);
	std::vector<Point> points(count);
	std::vector<ge_dsmp> precomp(count);
	std::vector<crypto::EllipticCurvePoint> bytes(count);
	std::vector<std::pair<Scalar, Point>> merged_sp(count);
	auto merged_double_points =
	    std::make_unique<std::tuple<Scalar, Scalar, Point, Point>[]>(count);  // Also ok in C++14

	// initialize random values for tests
	for (size_t i = 0; i < count; ++i) {
		KeyPair k      = random_keypair();
		bytes[i]       = k.public_key;
		auto s         = k.secret_key;
		auto p         = crypto::P3(k.public_key).p3;
		scalars[i]     = s;
		points[i]      = p;
		public_keys[i] = to_bytes(p);
		memcpy(derivations[i].data, public_keys[i].data, sizeof(EllipticCurvePoint));
		merged_sp[i] = std::make_pair(s, p);

		k                             = random_keypair();
		auto s2                       = k.secret_key;
		auto p2                       = crypto::P3(k.public_key).p3;
		merged_double_points.get()[i] = std::make_tuple(s, s2, p, p2);

		ge_dsm_precomp(&precomp[i], &p);
	}

	std::map<std::string, BenchmarkResult> benchmark_results;

	// run the benchmarks
	benchmark_results["frombytes"]        = benchmark(count * 10, test_frombytes, bytes);
	benchmark_results["fromfe_frombytes"] = benchmark(count * 10, test_fromfe_frombytes, bytes);
	benchmark_results["check_subgroup"]   = benchmark(count, test_check_subgroup, points);
	benchmark_results["derive_output_secret_key"] =
	    benchmark(count * 10, test_derive_output_secret_key, mk_vec(derivations, scalars));
	benchmark_results["double_scalarmult_base"] =
	    benchmark(count, test_double_scalarmult_base, mk_vec(scalars, points));
	benchmark_results["double_scalarmult_badprecomp"] =
	    benchmark(count, test_double_scalarmult_badprecomp, mk_vec(scalars, points));
	benchmark_results["double_scalarmult_simple"] =
	    benchmark(count, test_double_scalarmult_simple, mk_vec(scalars, points));
	benchmark_results["double_scalarmult_simple_opt"] =
	    benchmark(count, test_double_scalarmult_simple_opt, mk_vec(scalars, points));
	benchmark_results["double_scalarmult_simple_aligned"] =
	    benchmark(count, test_double_scalarmult_simple_aligned, mk_vec(scalars, scalars, points, points));
	benchmark_results["generate_key_derivation"] =
	    benchmark(count, test_generate_key_derivation, mk_vec(scalars, public_keys));
	benchmark_results["generate_signature"] = benchmark(count, test_generate_signature, mk_vec(public_keys, scalars));
	benchmark_results["scalarmult_base"]    = benchmark(count, test_scalarmult_base, scalars);
	benchmark_results["scalarmult"]         = benchmark(count, test_scalarmult, mk_vec(scalars, points));
	benchmark_results["scalarmult_via_phantom_point"] =
	    benchmark(count, test_scalarmult_via_phantom_point, mk_vec(scalars, points));
	benchmark_results["double_scalarmult"] = benchmark(count, test_double_scalarmult, mk_vec(scalars, points));
	benchmark_results["sc_mul"]            = benchmark(count * 1000, test_sc_mul, mk_vec(scalars, scalars));
	benchmark_results["sc_sub"]            = benchmark(count * 1000, test_sc_sub, mk_vec(scalars, scalars));
	benchmark_results["sc_mul_sub"] = benchmark(count * 1000, test_sc_mul_sub, mk_vec(scalars, scalars, scalars));
	benchmark_results["sc_invert"]  = benchmark(count, test_sc_invert, scalars);
	//	benchmark_results["generate_output"]   = test_generate_output(count, points.data(), points.data());
	//	benchmark_results["claim_output"] = test_claim_output(count);

	pprint_benchmarks(out, benchmark_results);
}
