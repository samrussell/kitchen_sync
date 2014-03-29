#include <assert.h>
#include "vmac/vmac.h"

template <typename OutputStream>
struct RowPacker {
	RowPacker(Packer<OutputStream> &packer): packer(packer) {}

	template <typename DatabaseRow>
	void operator()(const DatabaseRow &row) {
		packer.pack_array_length(row.n_columns());

		for (size_t i = 0; i < row.n_columns(); i++) {
			if (row.null_at(i)) {
				packer.pack_nil();
			} else {
				packer << row.string_at(i);
			}
		}
	}

	Packer<OutputStream> &packer;
};

#define MAX_DIGEST_LENGTH MD5_DIGEST_LENGTH

struct Hash {
	inline std::string to_string() const { return string((uint8_t*)md_value, (uint8_t*)(md_value + 2)); }

	uint64_t md_value[2];
};

template <typename OutputStream>
inline void operator << (Packer<OutputStream> &packer, const Hash &hash) {
	packer.pack_raw((const uint8_t *)hash.md_value, sizeof(hash.md_value));
}

inline bool operator == (const Hash &hash, const string &str) {
	return (sizeof(hash.md_value) == str.length() && memcmp(str.c_str(), hash.md_value, sizeof(hash.md_value)) == 0);
}

struct RowHasher {
	RowHasher(): row_count(0), size(0), row_packer(*this), partial_used(0) {
		vmac_set_key((unsigned char *)"abcdefghijklmnop", &ctx);
	}

	const Hash &finish() {
		assert(VMAC_TAG_LEN == 16*8);
		memset(partial_buf + partial_used, 0, sizeof(partial_buf) - partial_used);
		hash.md_value[0] = vhash(partial_buf, partial_used, hash.md_value + 1, &ctx);
		return hash;
	}

	template <typename DatabaseRow>
	void operator()(const DatabaseRow &row) {
		row_count++;
		
		// pack the row to get a byte stream, and hash it as it is written
		row_packer.pack_array_length(row.n_columns());

		for (size_t i = 0; i < row.n_columns(); i++) {
			if (row.null_at(i)) {
				row_packer.pack_nil();
			} else {
				row_packer << row.string_at(i);
			}
		}
	}

	inline void update_hash(const uint8_t *buf, size_t bytes) {
		assert(!(bytes % 16)); // see vmac.h
		vhash_update((unsigned char *)buf, bytes, &ctx);
		size += bytes;
	}

	inline void write(const uint8_t *buf, size_t bytes) {
		if (partial_used) {
			// we already have some data (< 1 hashable block) in the buffer; calculate how much more can fit
			size_t partial_remaining = sizeof(partial_buf) - partial_used;

			if (bytes < partial_remaining) {
				// the given data isn't enough to fill up a hashable block, so just add it to the buffer
				memcpy(partial_buf + partial_used, buf, bytes);
				partial_used += bytes;
				return;
			}

			// the given data is enough to fill up a hashable block; do that and hash it
			memcpy(partial_buf + partial_used, buf, partial_remaining);
			update_hash(partial_buf, sizeof(partial_buf));
			bytes -= partial_remaining;
			buf   += partial_remaining;
			partial_used = 0;
			// fall through to deal with any remaining data
		}

		if (bytes >= sizeof(partial_buf)) {
			// the remaining data is enough to fill up at least one hashable block, hash those without copying
			size_t bytes_to_hash = bytes - bytes % sizeof(partial_buf);
			update_hash(buf, bytes_to_hash);
			bytes -= bytes_to_hash;
			buf   += bytes_to_hash;
			// fall through to deal with any remaining data
		}

		if (bytes) {
			// the remaining data isn't enough to fill up a hashable block, accumulate it and wait for more
			memcpy(partial_buf, buf, bytes);
			partial_used = bytes;
		}
	}

	vmac_ctx_t ctx;
	size_t row_count;
	size_t size;
	Packer<RowHasher> row_packer;
	uint8_t partial_buf[VMAC_NHBYTES];
	size_t partial_used;
	Hash hash;
};

struct RowLastKey {
	RowLastKey(const vector<size_t> &primary_key_columns): primary_key_columns(primary_key_columns) {
	}

	template <typename DatabaseRow>
	inline void operator()(const DatabaseRow &row) {
		// keep its primary key, in case this turns out to be the last row, in which case we'll need to send it to the other end
		last_key.resize(primary_key_columns.size());
		for (size_t i = 0; i < primary_key_columns.size(); i++) {
			last_key[i] = row.string_at(primary_key_columns[i]);
		}
	}

	const vector<size_t> &primary_key_columns;
	vector<string> last_key;
};

struct RowHasherAndLastKey: RowHasher, RowLastKey {
	RowHasherAndLastKey(const vector<size_t> &primary_key_columns): RowLastKey(primary_key_columns) {
	}

	template <typename DatabaseRow>
	inline void operator()(const DatabaseRow &row) {
		RowHasher::operator()(row);
		RowLastKey::operator()(row);
	}
};
