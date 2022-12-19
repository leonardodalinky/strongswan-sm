/*
 * Copyright (C) 2008 Martin Willi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/*
 * Created by luqichen on 2022/12/19.
 * Implementing SM4 algorithm.
*/

#include "sm4_plugin.h"

#include <library.h>
#include "sm4_crypter.h"

typedef struct private_sm4_plugin_t private_sm4_plugin_t;

/**
 * private data of sm4_plugin
 */
struct private_sm4_plugin_t {

	/**
	 * public functions
	 */
	sm4_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_sm4_plugin_t *this)
{
	return "sm4";
}

METHOD(plugin_t, get_features, int,
	private_sm4_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(CRYPTER, sm4_crypter_create),
			PLUGIN_PROVIDE(CRYPTER, ENCR_SM4, 16),    /*What does the last parameter mean?*/
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_sm4_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *sm4_plugin_create()
{
	private_sm4_plugin_t *this;

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

