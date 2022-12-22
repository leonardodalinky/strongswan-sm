/*
 * Created by luqichen on 2022/12/19.
 * Implementing SM4 algorithm.
 */

#include <string.h>

#include "sm4_crypter.h"
#include <gmssl/sm4.h>

typedef struct private_sm4_crypter_t private_sm4_crypter_t;
typedef u_char sm4_cblock[SM4_BLOCK_SIZE];

struct private_sm4_crypter_t{
    /**
	 * Public part of this class.
	 */
    sm4_crypter_t public;

    /*
	 * State of the crypter. Both encrypter and decrypter.
	 */
    SM4_CBC_CTX ctx_en;
    SM4_CBC_CTX ctx_de;
};

METHOD(crypter_t, decrypt, bool,
	private_sm4_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *decrypted)
{
	sm4_cblock ivb;
	uint8_t *out;

	out = data.ptr;
	if (decrypted)
	{
		*decrypted = chunk_alloc(data.len);
		out = decrypted->ptr;
	}
	memcpy(&ivb, iv.ptr, sizeof(sm4_cblock));
    size_t nblocks = (data.len % SM4_BLOCK_SIZE == 0) ? data.len/SM4_BLOCK_SIZE : data.len/SM4_BLOCK_SIZE + 1;     /*Calculate the num of blocks by myself, and input it to the function*/
	sm4_cbc_encrypt(&this->ctx_de.sm4_key, (uint8_t*)&ivb, data.ptr, nblocks, out);
	return TRUE;
}

METHOD(crypter_t, encrypt, bool,
	private_sm4_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *encrypted)
{
	sm4_cblock ivb;
	uint8_t *out;

	out = data.ptr;
	if (encrypted)
	{
		*encrypted = chunk_alloc(data.len);
		out = encrypted->ptr;
	}
	memcpy(&ivb, iv.ptr, sizeof(sm4_cblock));
    size_t nblocks = (data.len % SM4_BLOCK_SIZE == 0) ? data.len/SM4_BLOCK_SIZE : data.len/SM4_BLOCK_SIZE + 1; 
	sm4_cbc_decrypt(&this->ctx_en.sm4_key, (uint8_t*)&ivb, data.ptr, nblocks, out);
	return TRUE;
}

METHOD(crypter_t, get_block_size, size_t,
	private_sm4_crypter_t *this)
{
	return sizeof(sm4_cblock);
}

METHOD(crypter_t, get_iv_size, size_t,
	private_sm4_crypter_t *this)
{
	return sizeof(sm4_cblock);
}

METHOD(crypter_t, get_key_size, size_t,
	private_sm4_crypter_t *this)
{
	return SM4_KEY_SIZE;
}

METHOD(crypter_t, set_key, bool,
	private_sm4_crypter_t *this, chunk_t key)
{
	sm4_set_encrypt_key(&this->ctx_en.sm4_key, key.ptr);     /*Why there is both set encrypt_key and decrypt_key in the sm4.h? It's confusing.*/
    sm4_set_decrypt_key(&this->ctx_de.sm4_key, key.ptr);
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	private_sm4_crypter_t *this)
{
	memwipe(this, sizeof(*this));
	free(this);
}

/*
 * Described in header
 */
sm4_crypter_t *sm4_crypter_create(encryption_algorithm_t algo)
{
	private_sm4_crypter_t *this;

    if (algo != ENCR_SM4){
        return NULL;
    }

	INIT(this,
		.public = {
			.crypter = {
				.get_block_size = _get_block_size,
				.get_iv_size = _get_iv_size,
				.get_key_size = _get_key_size,
				.destroy = _destroy,
			},
		},
	);

    this->public.crypter.set_key = _set_key;
    this->public.crypter.encrypt = _encrypt;
    this->public.crypter.decrypt = _decrypt;

	return &this->public;
}
