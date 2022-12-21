#include "sm2_plugin.h"
#include "sm2_private_key.h"
#include "sm2_public_key.h"
#include "sm2_dh.h"

#include <library.h>

typedef struct private_sm2_plugin_t private_sm2_plugin_t;

/**
 * private data of sm2_plugin
 */
struct private_sm2_plugin_t {

	/**
	 * public functions
	 */
	sm2_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_sm2_plugin_t *this)
{
	return "sm2";
}

METHOD(plugin_t, get_features, int,
	private_sm2_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
        /* key exchange */
        PLUGIN_REGISTER(KE, sm2_dh_create),
 			PLUGIN_PROVIDE(KE, CURVE_SM2),
		/* private/public keys */
		PLUGIN_REGISTER(PRIVKEY, sm2_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_SM2),
		PLUGIN_REGISTER(PRIVKEY_GEN, sm2_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_SM2),
		PLUGIN_REGISTER(PUBKEY, sm2_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_SM2),
		/* signature schemes, private */
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_SM2_WITH_SM3),
		/* signature verification schemes */
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_SM2_WITH_SM3),
	};
	*features = f;

	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_sm2_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *sm2_plugin_create()
{
	private_sm2_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
